---
slice_id: T.T4
title: Annual SSDF Re-Attestation Workflow + Material-Change Detector
loop: T
status: done
commit: TBDT4HASH
completed_date: 2026-07-01
applicable_conditional: true
condition: CSP delivers software to ANY federal agency (civilian or defense) under a contract that references OMB M-22-18 / M-23-16 — including legacy contracts entered before OMB M-26-05 (Jan 23 2026) made the Common Form collection voluntary. Agencies that elect, post-M-26-05, to continue using the Common Form on a tailored / risk-based basis also bring the CSP into scope.
trigger_flag: "--ssdf-attestation"
trigger_env: CLOUD_EVIDENCE_SSDF_ATTESTATION
depends_on: [T.T3, "LOOP-A.A4 (submission-bundle WELL_KNOWN)", "Tracker DB (tracker/server/schema.sql baseline)"]
blocks: []
estimated_effort: medium
last_updated: 2026-07-01
---

# T.T4 — Annual SSDF Re-Attestation Workflow + Material-Change Detector

> Authoritative per-slice context for T.T4. Any future session can ship
> this slice with ONLY this file + `cloud-evidence/CLAUDE.md` +
> `cloud-evidence/docs/loops/LOOP-T-SPEC.md` +
> `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` loaded.
> The REO standard (CLAUDE.md) governs every line of production code.

## 1. Mission

T.T4 owns the **lifecycle layer** of the SSDF self-attestation programme:
every CISA Common Form PDF that T.T3 emits enters T.T4's tracker, which
then (a) computes the next-due re-attestation date per OMB M-22-18 /
M-23-16 cadence guidance, (b) watches the T.T2 satisfaction-matrix for
**material changes** that force interim re-attestation under the
M-23-16 "binding ... unless and until the software producer notifies"
clause, and (c) renders the operator-facing status pane that lists, for
every (product × federal agency) pair, the last submission and the next
due date with a colour-coded urgency level.

Concretely, T.T4 ships:

1. A typed annual-cadence engine (`core/ssdf-annual-attestation.ts`)
   that computes `next_due_at` per (product × agency × regime)
   using a deterministic policy table tied to the M-22-18 /
   M-23-16 / M-26-05 regime field stored alongside the submission.
2. A material-change detector (`core/ssdf-material-change-detector.ts`)
   that diffs successive snapshots of `out/ssdf-satisfaction-matrix.json`
   (T.T2's output) and emits a typed `MaterialChangeEvent` whenever a
   practice flips `satisfied → not-satisfied`, a new un-attestable task
   appears, a new EO-critical-software product is added, or a new
   AI-augmentation gap surfaces from T.T5.
3. A SQLite migration (`tracker/db/migrations/add-ssdf-attestations.sql`)
   adding four tracker tables: `ssdf_products`,
   `ssdf_attestation_submissions`, `ssdf_practice_overrides`,
   `ssdf_material_change_events`.
4. A React status pane (`tracker/ui/ssdf-attestation-status-pane.tsx`)
   rendering the per-(product × agency) due-date matrix with filter,
   CSV export, and a "force re-attestation" action that logs into the
   tracker audit log.

T.T4 is the **closing slice of LOOP-T**: once it ships, the loop is
operationally complete (annual cadence + material-change surveillance +
operator UI), with T.T5 layering the optional 800-218A AI augmentation
on top.

## 2. Authoritative sources (with verbatim quotes)

All sources accessed 2026-06-07.

### EO 14028 §4(n) — statutory taproot of self-attestation

- **Source:** Executive Order 14028, "Improving the Nation's
  Cybersecurity", May 12, 2021.
- **URL (pinned):** https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- **Date of access:** 2026-06-07.
- **Relevance to T.T4:** §4(n) directed DHS to recommend FAR contract
  language requiring suppliers to *attest to complying* with the
  EO-derived NIST guidance. OMB M-22-18 implemented that direction
  pending FAR Council action. T.T4 is the lifecycle layer that keeps
  the attestation current.
- **§4(n) verbatim** (publicly available text):

  > "Within 1 year of the date of this order, the Secretary of Homeland
  > Security, in consultation with the Attorney General, the Director of
  > the Office of Management and Budget, and the heads of such other
  > agencies as the Secretary deems appropriate, shall recommend to the
  > FAR Council contract language requiring suppliers of software
  > available for purchase by agencies to comply with, and attest to
  > complying with, any requirements issued pursuant to subsections
  > (g) through (k) of this section."

### OMB M-22-18 — initial mandate (Sep 14 2022)

- **Source:** OMB Memorandum M-22-18, "Enhancing the Security of the
  Software Supply Chain through Secure Software Development Practices",
  September 14, 2022.
- **URL (pinned):** https://bidenwhitehouse.archives.gov/wp-content/uploads/2022/09/M-22-18.pdf
- **Date of access:** 2026-06-07.
- **§II — scope verbatim** (paraphrased from the LOOP-T-SPEC verbatim
  block; PDF on disk at `docs/sources/omb-m-22-18.pdf`):

  > "This memorandum applies to all software (other than agency-developed
  > software) developed or experiencing major version changes to be
  > operated by the agency or on behalf of the agency."

- **§III timeline verbatim:**

  > "Agencies will be required to obtain a self-attestation from the
  > software producer before using the software... Agencies must collect
  > attestations from producers of critical software ... within 270 days
  > of the date of issuance of guidance ... and for all other software
  > ... within 365 days of the date of issuance of guidance."

  T.T4 reads these timelines from `ssdf-config.yaml`'s per-product
  `regime` field; the policy engine in
  `core/ssdf-annual-attestation.ts` honours whichever cadence the
  operator's contract incorporates.

### OMB M-23-16 — extension + cadence clarification (Jun 9 2023)

- **Source:** OMB Memorandum M-23-16, "Update to Memorandum M-22-18,
  Enhancing the Security of the Software Supply Chain through Secure
  Software Development Practices", June 9, 2023.
- **URL (pinned):** https://bidenwhitehouse.archives.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18-Enhancing-Software-Security.pdf
- **Date of access:** 2026-06-07.
- **§III — re-attestation cadence verbatim** (load-bearing for T.T4):

  > "Attestations are binding for future versions of the named software
  > product unless and until the software producer notifies the agencies
  > to which it previously submitted the form that its development
  > practices no longer conform to the required elements specified in
  > the attestation."

  This is the textual hook that makes T.T4's material-change detector
  load-bearing: the attestation is *self-perpetuating* until the
  producer surfaces a non-conformance. The detector is therefore the
  producer-side instrument that triggers the M-23-16 notification
  obligation.

- **§III — scope-triggering change verbatim:**

  > "The requirement applies to: (1) new software developed after
  > September 14, 2022; (2) existing software modified by major version
  > changes after that date; and (3) software to which the producer
  > delivers continuous changes to the software code."

  T.T4 honours all three triggers: (1) new-product event from
  `ssdf-config.yaml` introduces a row in `ssdf_products` with
  `created_at >= 2022-09-14`, (2) major-version change is detected via
  `ssdf-config.yaml` `major_version_pattern` regex against SBOM emit
  (LOOP-J.J3.b), (3) continuous-change products carry
  `continuous_delivery: true` and inherit the material-change detector
  as the only re-attestation trigger.

- **§III — POA&M extension verbatim:**

  > "If the software producer cannot attest to one or more of the
  > practices ... the producer ... shall identify those practices ... in
  > a documentation artifact, such as a POA&M, that describes how the
  > producer plans to mitigate any identified risks."

  T.T4's `ssdf_practice_overrides` table is where the operator records
  POA&M-extension acknowledgements per (product × practice × agency)
  so the status pane shows them rather than treating the gap as a
  blocking failure.

### OMB M-26-05 — risk-based rescission (Jan 23 2026)

- **Source:** OMB Memorandum M-26-05, "Adopting a Risk-based Approach
  to Software and Hardware Security", January 23, 2026.
- **URL (pinned):** https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05-Adopting-a-Risk-based-Approach-to-Software-and-Hardware-Security.pdf
- **Date of access:** 2026-06-07.
- **Verbatim** (per Wiley Law alert
  https://www.wiley.law/alert-OMB-Rescinds-Secure-Software-Development-Mandate-in-Favor-of-a-Risk-Based-Approach
  and Inside Government Contracts summary
  https://www.insidegovernmentcontracts.com/2026/02/omb-rescinds-the-common-form-secure-software-attestation-requirement/):

  > "Memoranda M-22-18 and M-23-16 are rescinded. Agencies may continue
  > to use the Common Form, the NIST Secure Software Development
  > Framework, and related resources on a tailored, risk-based basis."

  T.T4's policy engine therefore distinguishes four regimes:
  `m-22-18-mandatory`, `m-23-16-extended`, `m-26-05-tailored`,
  `post-m-26-05-future`. Each carries its own cadence (table in
  Section 6).

### NIST SP 800-218 v1.1 — substrate the attestation covers

- **Source:** NIST SP 800-218 v1.1, "Secure Software Development
  Framework (SSDF) v1.1: Recommendations for Mitigating the Risk of
  Software Vulnerabilities", February 2022.
- **URL (pinned):** https://csrc.nist.gov/pubs/sp/800/218/final
- **PDF URL:** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf
- **Date of access:** 2026-06-07.
- **§1 — applicability verbatim:**

  > "The Secure Software Development Framework (SSDF) is a set of
  > fundamental, sound, and secure software development practices based
  > on established secure software development practice documents from
  > organizations such as BSA, OWASP, and SAFECode."

- **§2 — practice groups:**

  > "The SSDF practices are organized into four groups: Prepare the
  > Organization (PO); Protect the Software (PS); Produce Well-Secured
  > Software (PW); and Respond to Vulnerabilities (RV)."

  T.T4 stores the per-practice satisfaction state per submission in
  `ssdf_attestation_submissions.matrix_sha256` (with the full matrix
  written to `tracker/storage/ssdf-attestations/{product}/{fy}/matrix.json`)
  so a later diff can compute the material-change set deterministically.

### NIST SP 800-218A IPD / Final — AI augmentation feed

- **Source:** NIST SP 800-218A, "Secure Software Development Practices
  for Generative AI and Dual-Use Foundation Models: An SSDF Community
  Profile", final July 26, 2024.
- **URL (pinned):** https://csrc.nist.gov/pubs/sp/800/218/a/final
- **Date of access:** 2026-06-07.
- **Foreword verbatim:**

  > "This Community Profile augments the SSDF (NIST SP 800-218) with
  > practices, tasks, recommendations, considerations, notes, and
  > informative references that are specifically related to AI model
  > development throughout the software development life cycle."

  T.T4's material-change detector subscribes to T.T5's augmented matrix
  emit so a gap that appears only in the AI-augmented view fires a
  material-change event (kind: `ai_augmentation_gap`) even when the
  base SSDF matrix is unchanged.

### CISA Secure Software Development Attestation Common Form (OMB Control 1670-0052)

- **Source:** CISA, Secure Software Development Attestation Common Form,
  OMB Control Number 1670-0052, finalised March 11, 2024.
- **URL (pinned):** https://www.cisa.gov/secure-software-attestation-form
- **PDF (form):** https://www.cisa.gov/sites/default/files/2024-03/Self-Attestation-Common-Form-03082024-FINAL.pdf
- **Federal Register notice:** https://www.federalregister.gov/documents/2023/11/16/2023-25251/agency-information-collection-activities-request-for-comment-on-secure-software-development
- **Date of access:** 2026-06-07.
- **OMB Control number** — T.T4's tracker `ssdf_attestation_submissions`
  stores `omb_control_number` verbatim:

  > "OMB Control No. 1670-0052"

- **Form Section IV — Attestation language verbatim**
  (PDF download at `docs/sources/cisa-common-form.pdf`;
  REQUIRES-RESEARCH: confirm verbatim text once PDF accessible to
  WebFetch; current capture is from the published Federal Register
  notice 2023-25251):

  > "I attest that the software listed within the scope of this form is
  > developed in conformity with the secure software development
  > practices identified in this attestation form."

  T.T4 records the signer name + role + signature date + signed-PDF
  SHA-256 in `ssdf_attestation_submissions` for chain-of-custody.

### CISA Repository for Software Attestations and Artefacts (RSAA)

- **Source:** CISA RSAA service page.
- **URL (pinned):** https://www.cisa.gov/resources-tools/services/repository-software-attestations-and-artifacts-rsaa
- **Date of access:** 2026-06-07.
- **Relevance to T.T4:** the operator submits the signed Common Form
  PDF + supporting BoE to the RSAA. T.T4 records the RSAA submission
  ID + timestamp in `ssdf_attestation_submissions.rsaa_submission_id`
  for chain-of-custody. T.T4 does **not** auto-submit (REO Rule 4 —
  human action); the operator uploads via the web form.

### Cross-references to other LOOP-T docs

- `docs/loops/LOOP-T-SPEC.md` §1, §3, §6 (data flow), §7 (test
  strategy) — load-bearing for T.T4's diff-detector design.
- `docs/loops/LOOP-T-RISKS.md` — T-R-A1 (M-26-05 rescission),
  T-R-A3 (FAR Council clause), T-R-D1 (UI scale) all bear directly on
  T.T4.
- `docs/slices/T/T.T3.md` — T.T4 consumes the signed-PDF SHA-256 +
  POA&M companion + matrix snapshot that T.T3 emits.
- `docs/slices/T/T.T2.md` — T.T4 ingests successive matrix snapshots.
- `docs/slices/T/T.T5.md` — T.T4 ingests AI augmentation events.
- `docs/CIRCIA-WORKFLOW.md` — when a material-change event is also a
  Covered Cyber Incident under CIRCIA, the T.T4 detector and the
  CIRCIA reporter fire independently (no coupling).

## 3. Scope

### In scope

- Lifecycle storage of every (product × federal agency) Common Form
  submission in `ssdf_attestation_submissions` with: submission_id,
  product_id, agency_id, regime, fiscal_year, submitted_at,
  next_due_at, signer_name, signer_role, signed_pdf_sha256,
  rsaa_submission_id (nullable), poam_companion_uuid (nullable),
  matrix_sha256, signer_attestation_text (verbatim).
- Annual cadence policy engine (regime-aware) computing `next_due_at`.
- Material-change detector watching successive matrix snapshots and
  emitting typed `MaterialChangeEvent` rows.
- Tracker UI status pane (`/ssdf/attestations`) rendering the per-
  (product × agency) due-date matrix with filter, CSV export, and a
  "force re-attestation" operator action.
- Tracker page (`/ssdf/products`) for product registry CRUD.
- Tracker page (`/ssdf/material-changes`) for the event log.
- CHANGELOG entry + STATUS row update + loop-spec status row update.

### NOT in scope (explicit non-goals)

- **Auto-submission to RSAA.** REO Rule 4: human action only. T.T4
  records the operator-supplied RSAA submission ID + timestamp.
- **PDF signing.** REO Rule 1 forbids fake cryptographic operations.
  The operator signs the unsigned canonical PDF (emitted by T.T3)
  outside the toolchain; T.T4 ingests the signed-PDF SHA-256.
- **Automatic POA&M generation.** T.T3 emits the POA&M companion;
  T.T4 only references it.
- **AI augmentation matrix generation.** T.T5 owns it; T.T4 ingests
  the augmented matrix snapshot.
- **DoD-specific equivalency portal.** LOOP-S owns DFARS equivalency.
  When a product has both `regime=m-22-18-mandatory` AND the LOOP-S
  conditional gate is set, T.T4 logs a `cross-loop-applicability`
  diagnostic but does not transform.

## 4. Inputs

| Input | Source | Schema reference |
|---|---|---|
| `out/ssdf-satisfaction-matrix.json` | T.T2 emit | `core/ssdf-satisfaction-matrix.ts` `SsdfSatisfactionMatrix` |
| `out/ssdf-common-form-{product}-{fy}.pdf` (unsigned) | T.T3 emit | binary canonical PDF |
| Operator-supplied signed-PDF SHA-256 + RSAA submission ID + signer info | tracker UI form (`/ssdf/attestations/new`) | `tracker/db/types.ts:NewSubmissionInput` |
| `ssdf-config.yaml` per-product config | operator-committed in repo | `core/ssdf-config.ts:SsdfConfig` |
| Tracker baseline DB | tracker baseline | `tracker/server/schema.sql` |
| Optional: `out/ssdf-ai-satisfaction-matrix.json` | T.T5 emit (conditional) | `core/ssdf-ai-extension.ts:AiAugmentedMatrix` |

`ssdf-config.yaml` per-product schema (excerpt) — load-bearing for T.T4:

```yaml
ssdf:
  products:
    - id: "prod-acme-saas"
      legal_name: "Acme SaaS Platform"
      regime: "m-26-05-tailored"   # one of: m-22-18-mandatory | m-23-16-extended | m-26-05-tailored | post-m-26-05-future
      critical_software: false
      continuous_delivery: true
      major_version_pattern: "^(\\d+)\\.0\\.0$"
      ai_enabled: false
      federal_agencies:
        - { id: "dot",  name: "U.S. Department of Transportation" }
        - { id: "doe",  name: "U.S. Department of Energy" }
        - { id: "nasa", name: "National Aeronautics and Space Administration" }
      cadence_override_days: null   # nullable; overrides regime default
      poam_extension_allowed: true  # M-22-18 §III.E safety valve
```

## 5. Outputs

### 5.1 Tracker DB tables (canonical schema)

Migration file
`tracker/db/migrations/add-ssdf-attestations.sql` is the source of
truth. Column names + types pinned here:

```sql
-- ssdf_products: product registry. Operator CRUD via /ssdf/products.
CREATE TABLE ssdf_products (
  id                    TEXT PRIMARY KEY,
  legal_name            TEXT NOT NULL,
  regime                TEXT NOT NULL CHECK (regime IN ('m-22-18-mandatory','m-23-16-extended','m-26-05-tailored','post-m-26-05-future')),
  critical_software     INTEGER NOT NULL DEFAULT 0,
  continuous_delivery   INTEGER NOT NULL DEFAULT 0,
  major_version_pattern TEXT NOT NULL,
  ai_enabled            INTEGER NOT NULL DEFAULT 0,
  cadence_override_days INTEGER,
  poam_extension_allowed INTEGER NOT NULL DEFAULT 1,
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL
);

-- ssdf_attestation_submissions: per-(product × agency × fiscal-year) row.
CREATE TABLE ssdf_attestation_submissions (
  id                    TEXT PRIMARY KEY,
  product_id            TEXT NOT NULL REFERENCES ssdf_products(id) ON DELETE CASCADE,
  agency_id             TEXT NOT NULL,
  agency_name           TEXT NOT NULL,
  regime                TEXT NOT NULL,
  fiscal_year           TEXT NOT NULL,
  submitted_at          TEXT NOT NULL,
  next_due_at           TEXT NOT NULL,
  signer_name           TEXT NOT NULL,
  signer_role           TEXT NOT NULL CHECK (signer_role IN ('CEO','President','CISO','CTO','VP-Engineering','Chief-Compliance-Officer','designee')),
  designation_letter_sha256 TEXT,
  signed_pdf_sha256     TEXT NOT NULL,
  rsaa_submission_id    TEXT,
  rsaa_submitted_at     TEXT,
  poam_companion_uuid   TEXT,
  matrix_sha256         TEXT NOT NULL,
  matrix_storage_path   TEXT NOT NULL,
  signer_attestation_text TEXT NOT NULL,
  omb_control_number    TEXT NOT NULL DEFAULT '1670-0052',
  created_at            TEXT NOT NULL,
  superseded_by         TEXT
);
CREATE INDEX idx_ssdf_subs_product ON ssdf_attestation_submissions(product_id);
CREATE INDEX idx_ssdf_subs_due     ON ssdf_attestation_submissions(next_due_at);

-- ssdf_practice_overrides: per-(product × practice × agency) POA&M-extension acknowledgement.
CREATE TABLE ssdf_practice_overrides (
  id                  TEXT PRIMARY KEY,
  product_id          TEXT NOT NULL REFERENCES ssdf_products(id) ON DELETE CASCADE,
  practice_id         TEXT NOT NULL,
  agency_id           TEXT,
  poam_item_uuid      TEXT NOT NULL,
  acknowledged_at     TEXT NOT NULL,
  acknowledged_by     TEXT NOT NULL,
  mitigation_summary  TEXT NOT NULL,
  expires_at          TEXT
);

-- ssdf_material_change_events: detector output log.
CREATE TABLE ssdf_material_change_events (
  id                    TEXT PRIMARY KEY,
  product_id            TEXT NOT NULL REFERENCES ssdf_products(id) ON DELETE CASCADE,
  detected_at           TEXT NOT NULL,
  prior_matrix_sha256   TEXT NOT NULL,
  current_matrix_sha256 TEXT NOT NULL,
  change_kind           TEXT NOT NULL CHECK (change_kind IN ('practice_regression','new_untestable_practice','major_version_bump','ai_augmentation_gap','operator_forced','regime_change','agency_added')),
  practice_ids          TEXT NOT NULL,  -- comma-separated SSDF practice IDs
  triggers_reattestation INTEGER NOT NULL,
  notification_due_at   TEXT,
  notification_sent_at  TEXT,
  notified_agency_ids   TEXT,
  notes                 TEXT
);
CREATE INDEX idx_ssdf_events_product ON ssdf_material_change_events(product_id);
CREATE INDEX idx_ssdf_events_detected_at ON ssdf_material_change_events(detected_at);
```

### 5.2 Canonical-JSON snapshots

For every detector run, the snapshot used as the diff baseline lives at
`tracker/storage/ssdf-attestations/{product}/{fy}/matrix.json` with
SHA-256 stored alongside. The signed PDF lives next to it at
`tracker/storage/ssdf-attestations/{product}/{fy}/signed.pdf` (uploaded
by the operator via the UI).

### 5.3 Detector emit JSON (in-memory + tracker insert)

```ts
export interface MaterialChangeEvent {
  id: string;                       // uuid v4
  product_id: string;
  detected_at: string;              // ISO-8601 UTC
  prior_matrix_sha256: string;
  current_matrix_sha256: string;
  change_kind:
    | 'practice_regression'
    | 'new_untestable_practice'
    | 'major_version_bump'
    | 'ai_augmentation_gap'
    | 'operator_forced'
    | 'regime_change'
    | 'agency_added';
  practice_ids: string[];           // affected SSDF practice IDs (e.g. ["PO.1.1", "PW.7.2"])
  triggers_reattestation: boolean;
  notification_due_at: string | null;
  notified_agency_ids: string[];
  notes: string | null;
  provenance: {
    emitter: 'ssdf-material-change-detector';
    emittedAt: string;
    sourceCalls: Array<{
      kind: 'matrix' | 'config' | 'product-registry';
      path: string;
      sha256: string;
    }>;
    signingKeyId: string;
  };
}
```

### 5.4 Status-pane DTO (UI ingestion)

```ts
export interface AttestationStatusRow {
  product_id: string;
  product_legal_name: string;
  agency_id: string;
  agency_name: string;
  regime: 'm-22-18-mandatory' | 'm-23-16-extended' | 'm-26-05-tailored' | 'post-m-26-05-future';
  last_submission_id: string | null;
  last_submitted_at: string | null;
  next_due_at: string | null;
  due_state: 'current' | 'due_soon' | 'due_now' | 'overdue' | 'never_submitted';
  open_material_change_event_ids: string[];
  poam_extension_active: boolean;
}
```

## 6. Algorithm / Steps (numbered, deterministic, REO-compliant)

### Step 1 — Cadence policy engine

`core/ssdf-annual-attestation.ts` exports:

```ts
export interface CadencePolicy {
  regime: 'm-22-18-mandatory' | 'm-23-16-extended' | 'm-26-05-tailored' | 'post-m-26-05-future';
  base_cadence_days: number;       // default per regime
  critical_software_cadence_days: number;
  continuous_delivery_modifier_days: number;  // subtract from base if continuous_delivery=true
}

export const CADENCE_TABLE: Record<CadencePolicy['regime'], CadencePolicy> = {
  'm-22-18-mandatory':   { regime: 'm-22-18-mandatory',   base_cadence_days: 365, critical_software_cadence_days: 270, continuous_delivery_modifier_days: 0 },
  'm-23-16-extended':    { regime: 'm-23-16-extended',    base_cadence_days: 365, critical_software_cadence_days: 270, continuous_delivery_modifier_days: 0 },
  'm-26-05-tailored':    { regime: 'm-26-05-tailored',    base_cadence_days: 365, critical_software_cadence_days: 365, continuous_delivery_modifier_days: 0 },
  'post-m-26-05-future': { regime: 'post-m-26-05-future', base_cadence_days: 365, critical_software_cadence_days: 365, continuous_delivery_modifier_days: 0 },
};
```

`computeNextDueAt(product, submission)` returns
`submitted_at + cadence_days` (UTC, ISO-8601), where cadence_days is:

1. `product.cadence_override_days` if non-null (operator over-ride is
   honoured and logged).
2. Otherwise `critical_software_cadence_days` if
   `product.critical_software === true`.
3. Otherwise `base_cadence_days`.

The cadence value is **not** a hard deadline (the M-23-16 binding
clause keeps the attestation in force until notification); it is the
**internal due date** the producer uses to drive proactive
re-attestation review. Notification to the agency under M-23-16 is
triggered by the detector (Step 2), not by the cadence engine.

### Step 2 — Material-change detector

`core/ssdf-material-change-detector.ts` exports:

```ts
export function detectMaterialChange(
  prior: SsdfSatisfactionMatrix,
  current: SsdfSatisfactionMatrix,
  product: SsdfProduct,
  opts: { currentDate: string; aiAugmentation?: AiAugmentedMatrix },
): MaterialChangeEvent[];
```

Algorithm (deterministic):

1. **Compute per-practice status delta.** For each practice in `prior`,
   look up the same practice in `current`. If prior status was
   `satisfied` and current is one of `not-satisfied` |
   `requires-operator-input` and there is no active
   `ssdf_practice_overrides` row, emit `practice_regression`.
2. **Detect new un-attestable practices.** If `current` introduces a
   practice not in `prior` AND that practice's status is
   `not-satisfied`, emit `new_untestable_practice`.
3. **Detect major-version bump.** If `product.major_version_pattern`
   matches the current SBOM version (from LOOP-J.J3.b) and the prior
   submission's recorded version did not match, emit
   `major_version_bump`.
4. **Detect AI augmentation gap.** If `opts.aiAugmentation` is provided
   and the augmented matrix introduces a gap not present in the base
   matrix, emit `ai_augmentation_gap`.
5. **Detect regime change.** If `product.regime` differs from the
   regime stored in the most recent submission, emit `regime_change`.
6. **Detect agency added.** If `product.federal_agencies` adds an
   agency_id not present in any prior submission, emit
   `agency_added` (cadence engine will create a `never_submitted`
   row in the status pane).
7. **Compute `notification_due_at`.** Default policy: 14 calendar days
   after `detected_at` for `practice_regression` /
   `new_untestable_practice` / `ai_augmentation_gap`; 30 days for
   `major_version_bump` / `regime_change`; null for `agency_added`
   (informational only).
8. **Set `triggers_reattestation`.** True for `practice_regression` /
   `new_untestable_practice` / `major_version_bump` /
   `regime_change`; false for `ai_augmentation_gap` (handled by T.T5
   re-emit), `operator_forced` (handled out-of-band), and
   `agency_added` (handled by initial-submission flow).
9. **Determinism guarantee.** The detector is a pure function of
   (prior, current, product, opts) and is deterministic — same inputs
   produce byte-identical event arrays. The `id` field uses a uuid v5
   derived from
   `(product_id || prior_matrix_sha256 || current_matrix_sha256 || change_kind)`
   so re-runs produce the same UUID (idempotent insert).

### Step 3 — DB migration

`tracker/db/migrations/add-ssdf-attestations.sql` is applied by the
existing migration runner. Migration number is the next available
integer; the runner records it in `tracker_migrations`. Down-migration
drops the four tables in reverse-FK order.

### Step 4 — Tracker server endpoints

Add to `tracker/server/routes/ssdf.ts`:

- `GET    /api/ssdf/products`                          — list products
- `POST   /api/ssdf/products`                          — create
- `PUT    /api/ssdf/products/:id`                      — update
- `DELETE /api/ssdf/products/:id`                      — soft-delete
- `GET    /api/ssdf/submissions`                       — list (filterable)
- `POST   /api/ssdf/submissions`                       — create
- `GET    /api/ssdf/submissions/:id`                   — get
- `GET    /api/ssdf/status`                            — per-(product × agency) status DTO
- `GET    /api/ssdf/material-change-events`            — list events
- `POST   /api/ssdf/material-change-events/:id/notify` — mark notification sent
- `POST   /api/ssdf/products/:id/force-reattestation`  — emit `operator_forced` event
- `POST   /api/ssdf/detector/run`                      — manual re-run

All endpoints honour the existing RBAC (`ssdf-admin`, `ssdf-viewer`
roles added to `tracker/server/rbac.ts`) and the CSRF + rate-limit
middleware.

### Step 5 — Tracker UI status pane

`tracker/ui/ssdf-attestation-status-pane.tsx` is a React functional
component using the project's existing Tanstack-Table pattern. Columns:

| Column | Source | Sortable |
|---|---|---|
| Product | `product_legal_name` | yes |
| Federal Agency | `agency_name` | yes |
| Regime | `regime` (colour-coded) | yes |
| Last submitted | `last_submitted_at` (relative + ISO tooltip) | yes |
| Next due | `next_due_at` | yes |
| Due state | colour pill: green=`current`, amber=`due_soon` (within 60 days), red=`due_now` / `overdue`, grey=`never_submitted` | yes |
| Open material-change events | count link → detail page | yes |
| POA&M extension | boolean pill | yes |
| Actions | "View submissions" / "Force re-attestation" / "Mark notified" | — |

Filters: product, agency, regime, due state. CSV export reuses
`core/csv-export.ts` for the visible rows.

### Step 6 — Detector cron / on-demand trigger

The orchestrator wires the detector to run after every successful T.T2
emit (orchestrator step ordering: T.T2 → T.T4 detector → T.T3 if
needed). Manual trigger via tracker UI calls
`POST /api/ssdf/detector/run`.

### Step 7 — Provenance + signing

The detector's emit JSON carries a `provenance` block (REO Rule 2.6).
The tracker storage path
`tracker/storage/ssdf-attestations/{product}/{fy}/`
inherits the existing tracker storage encryption and is replicated by
the existing tracker backup pipeline.

### Step 8 — REO conformance checks

- No `process.env.NODE_ENV === 'test'` branches.
- No `TODO` / `FIXME` / `stub` / `placeholder` tokens in production
  paths.
- Every emit-field has a `provenance` entry.
- Tests inject seams via dependency-injected DB clients + clock.

### Step 9 — Completion procedure

After tests + typecheck pass, follow `docs/SLICE-COMPLETION-PROCEDURE.md`
verbatim. Section 13 below quotes the 7-step procedure.

## 7. Files to create / modify

### Files to create (absolute paths under `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/`)

- `core/ssdf-annual-attestation.ts` — cadence policy engine; pure
  module. ~250 lines.
- `core/ssdf-material-change-detector.ts` — diff detector; pure
  module. ~350 lines.
- `tracker/db/migrations/add-ssdf-attestations.sql` — 4 tables +
  indexes. ~120 lines.
- `tracker/server/routes/ssdf.ts` — REST routes (server-side). ~300
  lines.
- `tracker/server/services/ssdf-service.ts` — DB access layer. ~250
  lines.
- `tracker/ui/ssdf-attestation-status-pane.tsx` — React status pane.
  ~400 lines.
- `tracker/ui/ssdf-products-pane.tsx` — React product registry CRUD.
  ~300 lines.
- `tracker/ui/ssdf-material-changes-pane.tsx` — React event log.
  ~250 lines.
- `tests/core/ssdf-annual-attestation.test.ts` — unit tests for cadence
  engine. ~250 lines.
- `tests/core/ssdf-material-change-detector.test.ts` — unit + golden
  tests for detector. ~400 lines.
- `tests/tracker/ssdf-routes.test.ts` — REST endpoint tests. ~250
  lines.
- `tests/tracker/ssdf-status-pane.test.tsx` — React component tests
  (RTL). ~150 lines.
- `tests/fixtures/ssdf/` — fixtures: `matrix-prior.json`,
  `matrix-current-regression.json`,
  `matrix-current-new-untestable.json`,
  `matrix-current-ai-gap.json`, `product-fixture.json`,
  `submission-fixture.json`.

### Files to extend

- `tracker/server/schema.sql` — registers the migration.
- `tracker/server/rbac.ts` — add `ssdf-admin`, `ssdf-viewer` roles.
- `tracker/ui/router.tsx` — add `/ssdf/attestations`,
  `/ssdf/products`, `/ssdf/material-changes` routes.
- `tracker/ui/nav.tsx` — add "SSDF" section with the three pages.
- `core/orchestrator.ts` — wire detector to run after T.T2 emit when
  `--ssdf-attestation` is set.
- `docs/STATUS.md` — slice row + Overall section.
- `docs/loops/LOOP-T-SPEC.md` — slice status row in Section 3 + 12.
- `CHANGELOG.md` — Unreleased entry.
- `docs/loops/LOOP-T-RISKS.md` — append any newly-discovered risks.

## 8. Test specifications

Minimum 15 tests. Table:

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T.T4-T01 | Cadence engine: M-22-18 non-critical product → 365-day next_due_at | `tests/fixtures/ssdf/product-fixture.json` | `next_due_at = submitted_at + 365d` | `npm test -- ssdf-annual-attestation` passes |
| T.T4-T02 | Cadence engine: M-22-18 critical software → 270-day next_due_at | `tests/fixtures/ssdf/product-critical.json` | `next_due_at = submitted_at + 270d` | as above |
| T.T4-T03 | Cadence engine: operator override → override wins | `tests/fixtures/ssdf/product-override.json` (cadence_override_days=180) | `next_due_at = submitted_at + 180d` + audit log entry | as above |
| T.T4-T04 | Cadence engine: M-26-05 tailored → 365-day default | `tests/fixtures/ssdf/product-m2605.json` | `next_due_at = submitted_at + 365d` | as above |
| T.T4-T05 | Cadence engine: unknown regime → typed throw | `tests/fixtures/ssdf/product-bad-regime.json` | throws `InvalidRegimeError` | as above |
| T.T4-T06 | Detector: practice_regression event when satisfied → not-satisfied | `tests/fixtures/ssdf/matrix-prior.json` + `matrix-current-regression.json` | 1 event, kind=`practice_regression`, `triggers_reattestation=true`, `notification_due_at = detected_at + 14d` | `npm test -- ssdf-material-change-detector` passes |
| T.T4-T07 | Detector: no event when status flips with active POA&M override | `matrix-prior.json` + `matrix-current-regression.json` + `ssdf_practice_overrides` row | 0 events | as above |
| T.T4-T08 | Detector: new_untestable_practice when current introduces gap | `matrix-prior.json` + `matrix-current-new-untestable.json` | 1 event, kind=`new_untestable_practice`, `triggers_reattestation=true` | as above |
| T.T4-T09 | Detector: ai_augmentation_gap when only AI matrix changes | `matrix-prior.json` + `matrix-current-prior.json` + `ai-aug-gap.json` | 1 event, kind=`ai_augmentation_gap`, `triggers_reattestation=false` | as above |
| T.T4-T10 | Detector: major_version_bump when SBOM matches pattern | `product-fixture.json` + SBOM v2.0.0 (prior v1.5.3) | 1 event, kind=`major_version_bump`, `triggers_reattestation=true`, `notification_due_at = detected_at + 30d` | as above |
| T.T4-T11 | Detector: regime_change when product regime changes | `product-fixture.json` + product update | 1 event, kind=`regime_change`, `triggers_reattestation=true` | as above |
| T.T4-T12 | Detector: agency_added when new agency appears in config | `product-fixture.json` + new agency | 1 event, kind=`agency_added`, `triggers_reattestation=false`, `notification_due_at=null` | as above |
| T.T4-T13 | Detector: idempotent — same inputs produce same UUID | duplicate run | second-run insert is a no-op (uuid v5 collision) | as above |
| T.T4-T14 | Detector: provenance block present + signing key id recorded | any fixture | `provenance.emitter='ssdf-material-change-detector'` and `signingKeyId` present | `npm run check:provenance` passes |
| T.T4-T15 | Status DTO: never_submitted state for new agency | `product-fixture.json` + agency without prior submission | `due_state='never_submitted'`, `next_due_at=null` | `npm test -- ssdf-routes` passes |
| T.T4-T16 | Status DTO: due_soon state when within 60 days of next_due_at | submission `submitted_at = today - 310d` | `due_state='due_soon'` (between 60 days before and 0) | as above |
| T.T4-T17 | Status DTO: overdue state when past next_due_at | submission `submitted_at = today - 400d` | `due_state='overdue'` | as above |
| T.T4-T18 | REST: GET /api/ssdf/status returns 200 + per-row DTO | DB seeded | 200 + JSON array | `npm test -- ssdf-routes` passes |
| T.T4-T19 | REST: POST /api/ssdf/products denies non-admin caller | DB seeded + viewer token | 403 | as above |
| T.T4-T20 | UI: status pane renders due-state pill + CSV export | fixture row | snapshot matches; CSV download returns 200 + correct rows | `npm test -- ssdf-status-pane` passes |
| T.T4-T21 | REO no-stubs lint: production paths clean | all files | `npm run lint:no-stubs` exits 0 | check passes |

(21 tests authored — exceeds the 15 minimum.)

## 9. Risks

Per `docs/loops/LOOP-T-RISKS.md`. Minimum 4 risks specific to T.T4:

### Risk T.T4-R1 — Cadence drift vs M-23-16 binding clause

**Likelihood:** medium · **Impact:** high · **Severity:** high.

The M-23-16 binding clause states the attestation remains in force
"unless and until the software producer notifies the agencies." A naive
cadence engine that auto-marks a submission as `overdue` without
respect for the binding clause would mislead operators into believing
their attestation is invalid when it remains in force. **Mitigation:**
the cadence engine surfaces `next_due_at` as an *internal* review
deadline, not an expiration date. The UI labels the column "Next due
(internal review)" and tooltips that "the attestation remains binding
under M-23-16 §III until the producer notifies the agency". Material-
change events are the actual binding-clause trigger.

### Risk T.T4-R2 — Material-change false positive

**Likelihood:** medium · **Impact:** medium · **Severity:** medium.

The matrix `requires-operator-input` status is not a regression — it
is a coverage gap. If the detector treats every transition
`satisfied → requires-operator-input` as a regression, the operator
will be flooded with false positives whenever T.T2 introduces a new
evidence pointer that has not yet been wired. **Mitigation:** the
detector only emits `practice_regression` when the current status is
`not-satisfied` AND there is no active `ssdf_practice_overrides` row;
`requires-operator-input` is reported as a separate
`coverage:requires-input` log line, not as a material change.

### Risk T.T4-R3 — Operator-supplied notification SHA-256 / RSAA ID drift

**Likelihood:** medium · **Impact:** medium · **Severity:** medium.

The operator pastes the signed-PDF SHA-256 and the RSAA submission ID
into the tracker UI; a typo silently breaks chain-of-custody.
**Mitigation:** the tracker UI requires the operator to upload the
signed PDF (the server recomputes SHA-256 and stores it under
`tracker/storage/ssdf-attestations/{product}/{fy}/signed.pdf`);
the RSAA submission ID is validated against the regex
`^RSAA-[A-Z0-9]{8,16}$` plus a deduplication check; failures surface
inline before the row is persisted.

### Risk T.T4-R4 — UI scale with 100+ federal agencies × N products

**Likelihood:** low (initial) · medium (long-term) · **Impact:** medium · **Severity:** medium.

A producer with 10 products × 100 federal agencies = 1,000 status rows.
Default React rendering without pagination would degrade. **Mitigation:**
status pane uses virtual scrolling (Tanstack-Table virtualization)
already wired into the tracker baseline; default page size 50 with
filter chips; CSV export streams rows; per-product collapse + per-agency
collapse view modes.

### Risk T.T4-R5 — Cross-loop double-emission with LOOP-S material change

**Likelihood:** low · **Impact:** low · **Severity:** low.

A practice regression that also triggers a LOOP-S equivalency
re-attestation (e.g. the same PW.7.1 gap matters for both M-22-18 and
DFARS 252.204-7012) might fire twice. **Mitigation:** both loops emit
independent events with distinct `change_kind`; the tracker UI shows
both. The submission-bundle deduplicates POA&M items via UUID so
double-counting is impossible downstream.

### Risk T.T4-R6 — Regime change without back-fill

**Likelihood:** low · **Impact:** medium · **Severity:** medium.

When the operator changes a product's `regime` (e.g. from
`m-23-16-extended` to `m-26-05-tailored` after M-26-05 is itself
amended), prior submissions are still tagged with the old regime.
**Mitigation:** the cadence engine reads the regime stored on the
submission (immutable) for already-submitted rows; only new
submissions inherit the new regime. A `regime_change` event surfaces
in the log so the operator is aware.

## 10. Open questions

- **Q-T.T4-1**: Should the detector send an email / Slack notification
  to the operator when an event fires? **Resolution path**: yes,
  optionally; reuse `core/notify.ts`; default off (REO Rule 4: operator
  opts in).
- **Q-T.T4-2**: When the producer notifies an agency under the M-23-16
  binding clause, is the producer obligated to file a fresh Common Form
  immediately, or can they delay until the next cadence cycle?
  **Resolution path**: the M-23-16 text does not specify; the
  industry-default reading (Wiley alert, Crowell alert) is "immediately
  upon material change". T.T4 defaults `notification_due_at = detected_at + 14d`
  for regressions; the operator can extend by recording a justification
  in the event row.
- **Q-T.T4-3**: How does the tracker handle a product retirement?
  **Resolution path**: `ssdf_products.retired_at` (nullable column to
  add in a follow-up migration); status pane filters out retired
  products by default; retired-product rows are preserved for audit.
- **Q-T.T4-4**: When the operator's signing officer changes between
  cadence cycles, does that count as a material change? **Resolution
  path**: no by default (a corporate succession is not an SSDF
  practice change); the operator records the new officer in
  `ssdf_attestation_submissions.signer_name/role` on the next
  submission. A future T.T4 minor revision could add an
  `officer_change` event_kind (informational, `triggers_reattestation=false`).
- **Q-T.T4-5**: Should `cadence_override_days` accept a negative value
  (i.e. force a perpetually due state)? **Resolution path**: no; the
  schema CHECK constraint requires `cadence_override_days > 0`.
- **Q-T.T4-6**: For multi-product attestations (one form covering an
  entire product line under T.T3's `product_line` mode), does the
  detector treat the line as one product or N? **Resolution path**:
  T.T3 emits one matrix per product line; T.T4 stores the product line
  as a single `ssdf_products` row whose `id` is the line id; per-line
  cadence applies.

## 11. REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4, every field that cannot be auto-derived MUST be
operator-supplied via a documented pathway:

| Field | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|
| `ssdf_products.id` | string (slug) | regex `^[a-z0-9-]+$` | `/ssdf/products/new` form | Form rejects; explicit "product id required" error. |
| `ssdf_products.regime` | enum (4 values) | enum check in `core/ssdf-config.ts:isRegime()` | dropdown on product form | Form rejects with "regime is required". |
| `ssdf_products.critical_software` | boolean | boolean coerce | checkbox | Defaults `false` (NIST EO Critical Software definition not auto-derivable). |
| `ssdf_products.continuous_delivery` | boolean | boolean coerce | checkbox | Defaults `false`. |
| `ssdf_products.major_version_pattern` | string (regex) | regex parsability check | text field; default `^(\\d+)\\.0\\.0$` | Form rejects on invalid regex. |
| `ssdf_products.cadence_override_days` | int (nullable) | `> 0` if non-null | text field | Form rejects on `<=0`. |
| `ssdf_products.poam_extension_allowed` | boolean | boolean coerce | checkbox; default `true` | Defaults to `true` (M-22-18 §III.E permits). |
| `ssdf_attestation_submissions.agency_id` | string | regex `^[a-z0-9-]+$` | dropdown of `ssdf_products.federal_agencies` | Form rejects. |
| `ssdf_attestation_submissions.signer_name` | string | non-empty | text field | Form rejects. |
| `ssdf_attestation_submissions.signer_role` | enum (7 values) | enum check | dropdown | Form rejects on unknown role; `designee` requires `designation_letter_sha256`. |
| `ssdf_attestation_submissions.designation_letter_sha256` | string (hex) | hex 64-char | file upload (PDF) | Required iff `signer_role = 'designee'`; recompute on upload. |
| `ssdf_attestation_submissions.signed_pdf_sha256` | string (hex) | hex 64-char | file upload (signed PDF) | Server recomputes on upload; mismatch with operator-typed value is reported but recomputed value wins. |
| `ssdf_attestation_submissions.rsaa_submission_id` | string | regex `^RSAA-[A-Z0-9]{8,16}$` (when present) | text field | Nullable while pending RSAA submission; once present, deduplicated against prior rows. |
| `ssdf_attestation_submissions.rsaa_submitted_at` | ISO-8601 UTC | date check | datetime field | Required iff `rsaa_submission_id` is present. |
| `ssdf_attestation_submissions.poam_companion_uuid` | uuid | uuid v4 check | text field (pre-filled from T.T3 emit) | Required when any practice is not-satisfied + `poam_extension_allowed=true`. |
| `ssdf_practice_overrides.poam_item_uuid` | uuid | uuid v4 check | text field | Required when creating an override. |
| `ssdf_practice_overrides.mitigation_summary` | string | non-empty | textarea | Required. |
| `ssdf_practice_overrides.expires_at` | ISO-8601 UTC (nullable) | future date if present | datetime field | Optional; absence means override has no expiry. |
| `ssdf_material_change_events.notified_agency_ids` | string list | comma-joined slugs | multi-select | Populated when operator marks notification sent. |

For every missing required field, the relevant endpoint returns 400
with a `requires_operator_input` diagnostic naming the field and the
consumer artefact. The status pane surfaces the gap as a yellow pill.

## 12. Implementation log slot

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-07-01 | impl-t-t4 | Shipped the realizable core end-to-end: two pure engines — `core/ssdf-annual-attestation.ts` (regime-aware cadence policy table + `computeNextDueAt` internal-review date + `computeDueState`) and `core/ssdf-material-change-detector.ts` (matrix-diff detector emitting the 6 automated `MaterialChangeEvent` kinds + `computeStatusRows` + the signed `emitSsdfMaterialChanges` pass over a content-addressed on-disk snapshot ledger). Wired into the orchestrator under the existing `--ssdf-attestation` gate (after the T.T2 matrix emit, before T.T3/signing); 3 `submission-bundle` WELL_KNOWN roles + `ssdf_material_change_coverage` sibling; `config.yaml#ssdf.products[]` gained the optional T.T4 cadence fields. 29 new tests (12 cadence + 17 detector/status/emit), 1308/1308 passing, typecheck clean, `check:reo` green. | `TBDT4HASH` | **Realizable-core posture** (same as T.T2/T.T3/W.W3/W.W4): the spec §5.1/§5.4 SQLite tables + REST routes + React panes + RBAC + operator signed-PDF-SHA-256 / RSAA capture / force-reattestation / withdrawal / legal-review actions are **deferred** — no tracker subsystem in the repo (no `pg`/`express`/`react`/`better-sqlite3`); tracked as LOOP-T-RISKS `T.T4-21..24`. **Spec reconciliations:** (a) the §5.2 tracker-storage snapshot root relocated to `out/ssdf-attestation-snapshots/<product>/<sha256>.json` + `out/ssdf-attestation-ledger.jsonl`; (b) per-event provenance (§5.3) collapsed to a single file-level provenance block, consistent with the T.T2/T.T3 emit pattern; (c) the SBOM-version-driven `major_version_bump` + T.T5 `ai_augmentation_gap` inputs are wired via `DetectOptions` seams (unit-tested) but not fed by the orchestrator yet (no SBOM-version carry / no T.T5). §10 open questions resolved: Q1 (notify — deferred to tracker), Q2 (14-day regression notification default — implemented), Q5 (override must be > 0 — `InvalidCadenceOverrideError`). |

## 13. Completion checklist

Quote of the 7-step procedure from
`docs/SLICE-COMPLETION-PROCEDURE.md` (verbatim):

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

**Step 8 — slice-closure directive (T.T4-specific, beyond the 7
steps):** After commit lands, append a row to STATUS.md for this slice;
update the loop SPEC status row; append a CHANGELOG line; push to
origin/main; only THEN is the slice closed. If T.T4 is the final
LOOP-T slice (T.T5 has shipped earlier), mark LOOP-T (COMPLETE) in
STATUS.md and increment loops-complete. Update CLAUDE.md reading
list if any new permanent reference document was created.

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + algorithm
   + tests + risks + completion checklist + conditional gate.
3. Read `cloud-evidence/docs/loops/LOOP-T-SPEC.md` Sections 1, 2 (the
   M-22-18 / M-23-16 / M-26-05 verbatim quotes), 5 (reusable primitives),
   6 (data flow diagram), 7 (test strategy), 8 (risks summary), and
   13 (status table).
4. Read `cloud-evidence/docs/loops/LOOP-T-RISKS.md` for the full
   per-loop risks register; if T.T4 surfaces a new risk during
   implementation, append to that file in the same commit.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
6. Read `cloud-evidence/docs/slices/T/T.T3.md` to understand the input
   (signed-PDF SHA-256 + POA&M companion + matrix snapshot) T.T4
   ingests.
7. Read `cloud-evidence/docs/slices/T/T.T2.md` to understand the
   matrix shape T.T4 diffs.
8. Read `cloud-evidence/tracker/server/schema.sql` to confirm the
   migration runner integer + existing table conventions.
9. Read `cloud-evidence/tracker/ui/router.tsx` to confirm the React
   routing pattern.
10. Confirm `out/ssdf-satisfaction-matrix.json` exists (T.T2 must
    have shipped first); if not, run T.T2 first OR set up a fixture
    matrix under `tests/fixtures/ssdf/` and seed the tracker DB before
    running the detector end-to-end.
11. Begin implementation; update Implementation log section as you go.
12. Follow the 7-step completion procedure atomically with your final
    commit; update STATUS.md, LOOP-T-SPEC.md, CHANGELOG.md; push to
    origin/main.

---
