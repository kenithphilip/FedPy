---
slice_id: U.U3
title: DSAR Intake + Fulfillment Workflow (CCPA/CPRA 45-day + GDPR 1-month + Identity Verification)
loop: U
status: proposed
commit: TBD
completed_date: —
depends_on:
  - U.U2                                 # datastore-to-framework applicability map (which datastores carry CCPA/CPRA/GDPR/UK GDPR personal data)
  - LOOP-A.A4                            # submission bundler (DSAR fulfillment audit envelope inclusion)
  - LOOP-A.A5                            # Ed25519 + RFC 3161 signing of the DSAR audit envelope
  - tracker DB (existing)                # request intake form, status pane, audit-log table
blocks: []
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: When at least one privacy framework with data-subject rights (California CCPA / CPRA, EU GDPR, UK GDPR) applies to any datastore identified by U.U2. If U.U2's `applicability_matrix.frameworks_in_scope[]` includes any of {'ccpa','cpra','gdpr-eu','gdpr-uk'} the slice is REQUIRED. If U.U2 emits zero in-scope frameworks the slice is skipped (orchestrator records `coverage:dsar-workflow:not-applicable:1`). COPPA parental requests are routed through the same intake form but follow a separate verification path documented in §6 Phase D.
trigger_flag: "--dsar-workflow"
trigger_env: CLOUD_EVIDENCE_DSAR_WORKFLOW
---

# U.U3 — DSAR Intake + Fulfillment Workflow

> U.U3 is the **operator-facing fulcrum** of LOOP-U. U.U1 classifies the
> personal data, U.U2 maps datastores to frameworks; U.U3 is what the
> CSP actually hands a data subject when they request access, deletion,
> correction, portability, or opt-out. Because two non-aligned regulatory
> clocks (CCPA's 45 calendar days vs. GDPR's "without undue delay and in
> any event within one month") apply to the same request when the
> subject is dual-jurisdiction, and because the consequences of mis-
> verifying identity (Article 12(2) GDPR; Cal. Civ. Code §1798.140(ag))
> are themselves data-protection violations, this slice carries extra
> rigor: 18 tests (above the §8 floor of 15), an expanded risk register,
> and a step-by-step fulfillment algorithm that is fully deterministic
> from the trigger envelope alone.
>
> Like every per-slice doc in this corpus, U.U3 is **self-contained**:
> any fresh Claude session reading only this file plus
> `cloud-evidence/CLAUDE.md` can resume the slice end-to-end without
> re-deriving the regulatory clocks, the nine exempt categories of
> personal information under CCPA §1798.105(d), the GDPR Article
> 11(2)/12(6) identity-verification carve-outs, or the bundler envelope
> shape.

## 1. Mission

U.U3 ingests a Data Subject Access Request (DSAR) — submitted via the
tracker UI public-facing intake form, via an authenticated email-to-DB
relay (operator-configured webhook), or via a CSV bulk import for
agencies handling consolidated requests — and produces a signed,
timestamped fulfillment audit envelope plus the actual data
deliverables (a portable JSON export, a deletion-confirmation receipt,
a correction-log entry, or an opt-out registry record) that the operator
can deliver back to the data subject. The slice spans the full request
lifecycle: intake, identity verification, scoping (which datastores hold
the subject's data — drawn from U.U2's applicability matrix), per-right
handler dispatch, deadline-clock arithmetic, partial-fulfillment
branching (CCPA §1798.130(a)(2) 45-day extension; GDPR Art. 12(3)
two-month extension), and final closure with the audit envelope sealed
by LOOP-A.A5.

The slice does **not** transmit the deliverables to the data subject —
REO Rule 4 forbids the system from acting on behalf of the operator for
any externally-facing regulated communication. U.U3 produces the
artifact bundle (signed JSON envelope + portable export `.zip` for
access/portability, or signed deletion-receipt `.pdf` for deletion, or
signed correction-log for correction), surfaces the bundle in the
tracker UI with a live countdown timer to the earlier of the two
applicable deadlines (CCPA 45 days vs. GDPR 1 month, whichever expires
first), and records every operator action (delivery timestamp +
delivery channel + subject acknowledgement reference) as a signed audit
log entry. When the deadline is at risk of being missed, U.U3
escalates: the T-7-day notification routes to the operator's Privacy
Officer (configurable per `dsar-config.yaml`), and the tracker UI
banner turns amber at T-7, red at T-3, and shows a hard-block "DEADLINE
MISSED" treatment after expiry.

U.U3 also implements the **30-day extension paths** allowed under both
frameworks — CCPA §1798.130(a)(2)(A) permits a single 45-day extension
"when reasonably necessary"; GDPR Article 12(3) permits a two-month
extension "taking into account the complexity and number of the
requests". The extension path requires explicit operator opt-in
(tracker UI button, audit-logged) and emits a separate
"extension-notice" envelope to the data subject's acknowledgement
channel within the original deadline window (a hard requirement under
both regimes — failing to notify the subject of the extension within
the original window is itself a violation).

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live source returned a non-200 to anonymous
fetches, the implementer downloads the page or PDF to
`cloud-evidence/docs/sources/` and re-quotes verbatim from the local
copy.

### 2.1 California Consumer Privacy Act (CCPA) — Cal. Civ. Code §1798.130 — Request response timing

URL: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.130 (accessed 2026-06-07).

§1798.130(a)(2)(A) — the **45-day clock** and the **single extension**:

> "Disclose and deliver, free of charge to the consumer, the personal
> information required by this section within 45 days of receiving a
> verifiable consumer request from the consumer. The business shall
> promptly take steps to determine whether the request is a verifiable
> consumer request, but this shall not extend the business's duty to
> disclose and deliver the information within 45 days of receipt of the
> consumer's request. The time period to provide the required
> information may be extended once by an additional 45 days when
> reasonably necessary, provided the consumer is provided notice of the
> extension within the first 45-day period."

The clause has **three** operationally material features that shape
U.U3:

1. The clock is **calendar days, not business days** — see Risk 1 for
   the operational fallout (no holiday-skip math).
2. Identity verification ("verifiable consumer request") does not toll
   the clock — the 45 days run from receipt regardless of when the
   operator finishes verifying. U.U3 starts the clock at `intake_at`
   and treats verification as a parallel workflow.
3. The single 45-day extension requires **proactive notice to the
   consumer within the first 45-day period**, not a passive flip of an
   internal flag. U.U3 emits an `extension-notice` envelope on operator
   opt-in.

§1798.130(a)(2)(B) — **scope of the response**:

> "The business shall provide the information in a portable and, to the
> extent technically feasible, readily useable format that allows the
> consumer to transmit this information to another entity without
> hindrance. The business may provide personal information to a
> consumer at any time, but shall not be required to provide personal
> information to a consumer more than twice in a 12-month period."

The portability requirement maps to U.U3's
`portable-export-bundle.zip` deliverable (canonical JSON + per-category
CSV under U.U3's `dsar-export-bundler.ts`). The twice-in-12-months
limit maps to U.U3's intake-side throttle check against the
`dsar_requests` table.

### 2.2 California Consumer Privacy Act (CCPA) — Cal. Civ. Code §1798.105 — Right to deletion + nine exemptions

URL: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.105 (accessed 2026-06-07).

§1798.105(a) and §1798.105(d) — the **deletion right** and the **nine
business-purpose exemptions** the operator may invoke:

> "A consumer shall have the right to request that a business delete
> any personal information about the consumer which the business has
> collected from the consumer."

> "(d) A business or a service provider shall not be required to comply
> with a consumer's request to delete the consumer's personal
> information if it is necessary for the business or service provider
> to maintain the consumer's personal information in order to:
> (1) Complete the transaction for which the personal information was
> collected, provide a good or service requested by the consumer, or
> reasonably anticipated within the context of a business's ongoing
> business relationship with the consumer, or otherwise perform a
> contract between the business and the consumer.
> (2) Detect security incidents, protect against malicious, deceptive,
> fraudulent, or illegal activity; or prosecute those responsible for
> that activity.
> (3) Debug to identify and repair errors that impair existing intended
> functionality.
> (4) Exercise free speech, ensure the right of another consumer to
> exercise that consumer's right of free speech, or exercise another
> right provided for by law.
> (5) Comply with the California Electronic Communications Privacy Act
> pursuant to Chapter 3.6 (commencing with Section 1546) of Title 12 of
> Part 2 of the Penal Code.
> (6) Engage in public or peer-reviewed scientific, historical, or
> statistical research in the public interest that adheres to all other
> applicable ethics and privacy laws, when the business's deletion of
> the information is likely to render impossible or seriously impair
> the achievement of such research, if the consumer has provided
> informed consent.
> (7) To enable solely internal uses that are reasonably aligned with
> the expectations of the consumer based on the consumer's relationship
> with the business.
> (8) Comply with a legal obligation.
> (9) Otherwise use the consumer's personal information, internally, in
> a lawful manner that is compatible with the context in which the
> consumer provided the information."

U.U3 implements deletion as a **two-phase confirmation**: phase 1 is
the operator-side exemption-claim form (one row per (datastore, record)
pair; operator selects which exemption (if any) applies, with a
free-text justification logged to the audit envelope); phase 2 is the
actual deletion call against the underlying datastore (via U.U2's
datastore manifest). Records claimed under an exemption are NOT
deleted; the envelope to the consumer carries an
`exemption_disclosure` block citing the specific subsection and the
operator's justification (CPRA §1798.130(a)(3)(B) requires this
disclosure).

### 2.3 General Data Protection Regulation (GDPR) — Regulation (EU) 2016/679 — Article 12 (transparent information, communication) + Article 15 (right of access)

URL: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02016R0679-20160504 (accessed 2026-06-07).

Article 12(3) — the **one-month clock** and the **two-month extension**:

> "The controller shall provide information on action taken on a
> request under Articles 15 to 22 to the data subject without undue
> delay and in any event within one month of receipt of the request.
> That period may be extended by two further months where necessary,
> taking into account the complexity and number of the requests. The
> controller shall inform the data subject of any such extension within
> one month of receipt of the request, together with the reasons for
> the delay. Where the data subject makes the request by electronic
> form means, the information shall be provided by electronic means
> where possible, unless otherwise requested by the data subject."

Three features shape U.U3:

1. **"One month"** is interpreted per Article 3(3) of Council
   Regulation (EEC, Euratom) No 1182/71 — see §2.4 below — meaning the
   clock ends on the same numbered day of the next calendar month, NOT
   30 days. A request received on Jan 31 expires Feb 28 (or 29 in a
   leap year); a request received on Mar 31 expires Apr 30. U.U3's
   clock module implements this rule.
2. The two-month extension is conditional on **"complexity and number
   of the requests"** — the operator must record a justification in
   the audit envelope. U.U3 prompts for the justification at the
   extension-opt-in moment.
3. Notice of the extension is due **within the original one-month
   window** — same proactive-notice requirement as CCPA.

Article 12(6) — the **identity-verification carve-out**:

> "Without prejudice to Article 11, where the controller has reasonable
> doubts concerning the identity of the natural person making the
> request referred to in Articles 15 to 21, the controller may request
> the provision of additional information necessary to confirm the
> identity of the data subject."

Article 11(2) — the **excess-information limit**:

> "Where, in cases referred to in paragraph 1 of this Article, the
> controller is able to demonstrate that it is not in a position to
> identify the data subject, the controller shall inform the data
> subject accordingly, if possible. In such cases, Articles 15 to 20
> shall not apply except where the data subject, for the purpose of
> exercising his or her rights under those articles, provides
> additional information enabling his or her identification."

These two clauses bind U.U3's identity verifier. The verifier MUST NOT
demand more identity data than is strictly necessary; in the absence of
account credentials the verifier may request a government-issued ID
hash or a verification challenge to a known channel, but the operator
configures the verification ladder per `dsar-identity-policy.yaml` (§11).

Article 15(1) — **scope of the access right** (read by U.U3's
`dsar-export-bundler.ts`):

> "The data subject shall have the right to obtain from the controller
> confirmation as to whether or not personal data concerning him or her
> are being processed, and, where that is the case, access to the
> personal data and the following information:
> (a) the purposes of the processing;
> (b) the categories of personal data concerned;
> (c) the recipients or categories of recipient to whom the personal
> data have been or will be disclosed, in particular recipients in
> third countries or international organisations;
> (d) where possible, the envisaged period for which the personal data
> will be stored, or, if not possible, the criteria used to determine
> that period;
> (e) the existence of the right to request from the controller
> rectification or erasure of personal data or restriction of
> processing of personal data concerning the data subject or to object
> to such processing;
> (f) the right to lodge a complaint with a supervisory authority;
> (g) where the personal data are not collected from the data subject,
> any available information as to their source;
> (h) the existence of automated decision-making, including profiling,
> referred to in Article 22(1) and (4) and, at least in those cases,
> meaningful information about the logic involved, as well as the
> significance and the envisaged consequences of such processing for
> the data subject."

U.U3's portable export bundle includes all eight (a)–(h) blocks as
distinct files; the operator's `dsar-config.yaml` pre-declares the
processing purposes, recipient categories, retention rules, and
automated-decision-making logic (sourced from U.U2 + LOOP-O for AI
systems where applicable).

### 2.4 Council Regulation (EEC, Euratom) No 1182/71 — Time periods

URL: https://eur-lex.europa.eu/eli/reg/1971/1182/oj (accessed 2026-06-07).

Article 3(2)(c) — **how "a month" is computed**:

> "(c) a period expressed in weeks, months or years shall start at the
> beginning of the first hour of the first day of the period, and
> shall end with the expiry of the last hour of whichever day in the
> last week, month or year is the same day of the week, or falls on
> the same date, as the day from which the period runs. If, in a
> period expressed in months or in years, the day on which it should
> expire does not occur in the last month, the period shall end with
> the expiry of the last hour of the last day of that month."

This regulation is the **authoritative source** for GDPR's "one month"
arithmetic. The Article 29 Working Party Guidelines on transparency
(WP260 rev.01) explicitly cite this regulation as the calculation rule
for Article 12(3). U.U3's clock module implements §3(2)(c) verbatim.

### 2.5 UK GDPR — Data Protection Act 2018 (UK) — Section 7 — applied GDPR

URL: https://www.legislation.gov.uk/ukpga/2018/12/section/7/enacted (accessed 2026-06-07).

§7 of the DPA 2018 incorporates the GDPR into UK law with the same
one-month clock + identity-verification rules. The Information
Commissioner's Office (ICO) guidance on the right of access (URL:
https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/right-of-access/
accessed 2026-06-07) provides the operational reading:

> "You have one month to respond to a request. You can extend the time
> limit by a further two months if the request is complex or you have
> received a number of requests from the individual. You must let the
> individual know within one month of receiving their request and
> explain why the extension is necessary."

U.U3 treats `'gdpr-uk'` as a separate framework code (distinct from
`'gdpr-eu'`) in the applicability matrix so that post-Brexit divergence
in supervisory-authority routing (UK ICO vs. EU national DPAs) is
captured. The deadline math is identical.

### 2.6 NIST SP 800-63A-3 — Enrollment and Identity Proofing

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63a.pdf (accessed 2026-06-07).

§4.2 — the **Identity Assurance Level (IAL)** framework that U.U3's
`dsar-identity-verifier.ts` maps DSAR identity proofing onto:

> "Identity Assurance Level (IAL): The robustness of the identity
> proofing process used to verify a subscriber's identity.
> IAL1: There is no requirement to link the applicant to a specific
> real-life identity. Any attributes provided in conjunction with the
> authentication process are self-asserted or should be treated as such.
> IAL2: Evidence supports the real-world existence of the claimed
> identity and verifies that the applicant is appropriately associated
> with this real-world identity. IAL2 introduces the need for either
> remote or physically-present identity proofing. Attributes can be
> asserted by CSPs to RPs in support of pseudonymous identity with
> verified attributes.
> IAL3: Physical presence is required for identity proofing. Identifying
> attributes must be verified by an authorized and trained
> representative of the CSP."

U.U3 maps the operator's `dsar-identity-policy.yaml` selection to one
of IAL1/IAL2/IAL3. Default is IAL2 (the GDPR/CCPA-recommended floor
for high-risk-data DSARs). The operator may downgrade to IAL1 for
low-risk datastores (anonymous newsletter sign-ups) or escalate to IAL3
for special-category data (Article 9 GDPR) where the regulator's
guidance recommends stronger proofing. The verifier records the IAL
applied in the audit envelope and refuses to advance to fulfillment if
the verification ladder did not complete.

### 2.7 California Privacy Rights Act (CPRA) — Cal. Civ. Code §1798.140 — Verifiable consumer request definition

URL: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140 (accessed 2026-06-07).

§1798.140(ag) — the **verifiable consumer request** definition (CPRA
imports the original CCPA definition with a clarifying CPRA amendment):

> "'Verifiable consumer request' means a request that is made by a
> consumer, by a consumer on behalf of the consumer's minor child, or
> by a natural person or a person registered with the Secretary of
> State, authorized by the consumer to act on the consumer's behalf,
> or by a person who has power of attorney or is acting as a
> conservator for the consumer, and that the business can reasonably
> verify, pursuant to regulations adopted by the Attorney General
> pursuant to paragraph (7) of subdivision (a) of Section 1798.185 to
> be the consumer about whom the business has collected personal
> information. A business is not obligated to provide information to
> the consumer pursuant to Sections 1798.110 and 1798.115 if the
> business cannot verify, pursuant to this subdivision and regulations
> adopted by the Attorney General pursuant to paragraph (7) of
> subdivision (a) of Section 1798.185, that the consumer making the
> request is the consumer about whom the business has collected
> information or is a person authorized by the consumer to act on such
> consumer's behalf."

This grants the operator the **right to refuse fulfillment** if
identity cannot be verified — but the refusal itself must be
documented and disclosed to the consumer with the reason. U.U3's
`refusal-notice` path emits a separate signed envelope citing
§1798.140(ag) with the verification attempts logged in
machine-readable form.

### 2.8 Children's Online Privacy Protection Act (COPPA) — 16 CFR §312.6 — Parent's right to review

URL: https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312/section-312.6 (accessed 2026-06-07).

§312.6(a) — **parental review and deletion rights**:

> "(a) Upon request of a parent whose child has provided personal
> information to a Web site or online service, the operator of that
> Web site or online service is required to provide to that parent the
> following:
> (1) A description of the specific types or categories of personal
> information collected from children by the operator;
> (2) The opportunity at any time to refuse to permit the operator's
> further use or future online collection of personal information from
> that child, and to direct the operator to delete the child's personal
> information; and
> (3) Notwithstanding any other provision of law, a means that is
> reasonable under the circumstances for the parent to obtain any
> personal information collected from that child."

COPPA parental requests route through U.U3's intake form (with a
separate sub-form for `discovery_kind = 'coppa-parental-request'`), but
the identity-verification ladder is distinct: the COPPA verifier
verifies the parent's identity AND the parent-child relationship via
the FTC-approved methods enumerated in 16 CFR §312.5(b)(2) (credit
card transaction, signed consent form, video call with government ID,
etc.). U.U3 records the COPPA verification method applied in the audit
envelope.

## 3. Scope

### In scope (this slice)

- **Intake**: tracker UI public-facing form (rendered at
  `/dsar/intake` route by `tracker/ui/dsar-intake-page.tsx` — note:
  the page lives in U.U1's slice; U.U3 owns the API binding); CSV
  bulk-import for agency-coordinated requests; authenticated email-to-DB
  relay via operator-configured webhook to `POST /api/dsar/intake`.
- **Identity verification ladder**: IAL1/IAL2/IAL3 path per
  `dsar-identity-policy.yaml`; COPPA-specific verifier for parental
  requests.
- **Scoping**: applicability matrix lookup against U.U2's datastore
  manifest — which datastores hold this subject's data.
- **Per-right handler dispatch**:
  - Access (CCPA §1798.110; GDPR Art. 15)
  - Deletion (CCPA §1798.105; GDPR Art. 17)
  - Correction (CPRA §1798.106; GDPR Art. 16)
  - Portability (CCPA §1798.130(a)(2)(B); GDPR Art. 20)
  - Opt-out of sale/share (CPRA §1798.135; GDPR not applicable but
    Art. 21 right to object overlaps for marketing)
- **Deadline-clock arithmetic** for both CCPA (45 calendar days) and
  GDPR (one calendar month per Reg 1182/71 Art 3(2)(c)) with
  extension paths.
- **Audit envelope** signed by LOOP-A.A5; bundled by LOOP-A.A4.
- **Operator notifications** at T-7-day and T-3-day before earlier
  deadline; deadline-missed banner.

### Out of scope (deferred to other slices)

- **Transmission to the data subject** (REO Rule 4 forbids — operator
  hand-delivers).
- **The intake-form page itself** (lives in U.U1 — U.U3 only owns the
  API and the status-pane UI extension).
- **U.U2's applicability matrix construction** (consumed read-only).
- **Subprocessor downstream propagation** (deferred to U.U4 — when a
  subprocessor must also fulfill a deletion request).
- **Privacy Impact Assessment regeneration** (handled by LOOP-M).
- **GDPR Article 22 automated-decision-making explanation** (handled
  by LOOP-O.O3 — U.U3 references LOOP-O's emitted explanation
  artifact for inclusion in the (h) block of the access export, but
  does not generate it).

## 4. Inputs

```typescript
// DSAR intake — the canonical input shape used by the API endpoint and
// the CSV bulk-import parser. Every field has a precise validator in
// dsar-intake.ts; see §6 Phase A for the validation order.
interface DsarIntakeRequest {
  request_id: string;                    // ULID, generated server-side
  intake_at: string;                     // ISO8601 with TZ; server clock
  channel: 'web-form' | 'email-relay' | 'csv-bulk-import' | 'mail-fax-manual';

  // Subject identification (claimed, not yet verified)
  claimed_identity: {
    primary_identifier_kind:             // determines which verifier ladder
      'email' | 'account-id' | 'phone' | 'name+address' |
      'government-id-hash' | 'parent-of-minor';
    primary_identifier_value_hash: string; // SHA-256 of the claim; raw value stored encrypted-at-rest
    secondary_identifiers: Array<{       // operator may require N≥2 per IAL2
      kind: string;
      value_hash: string;
    }>;
    jurisdictional_self_assertion: {     // subject declares residence
      country: string;                   // ISO 3166-1 alpha-2
      state_or_province?: string;        // ISO 3166-2 (e.g. 'US-CA')
    };
  };

  // Right(s) being exercised — one request may exercise multiple
  rights_requested: Array<
    'access' | 'deletion' | 'correction' | 'portability' |
    'opt-out-sale' | 'opt-out-share' | 'opt-out-targeted-advertising' |
    'object-marketing' | 'restrict-processing' | 'coppa-parental-review' |
    'coppa-parental-deletion'
  >;

  // Correction-specific payload (when 'correction' in rights_requested)
  correction_payload?: Array<{
    target_field: string;                // dotted-path into the datastore record
    current_value_hash: string;          // SHA-256 — subject claims this is what's stored
    proposed_value: string;              // the operator validates + applies
  }>;

  // Free-text statement supplied by the subject
  subject_statement: string;             // max 4000 chars; HTML-stripped

  // Operator-side fields populated server-side after intake
  applicable_frameworks: Array<          // computed from claimed_identity + U.U2 lookup
    'ccpa' | 'cpra' | 'gdpr-eu' | 'gdpr-uk' | 'coppa' | 'glba' | 'ferpa'
  >;
  applicable_datastores: string[];       // U.U2 datastore_ids that may hold this subject's data
  deadline_ccpa_at: string | null;       // intake_at + 45 calendar days; null if CCPA not applicable
  deadline_gdpr_at: string | null;       // intake_at + 1 calendar month per Reg 1182/71; null if GDPR not applicable
  earliest_deadline_at: string;          // min(non-null deadlines); the operational countdown

  // Verification state (mutated as the verifier advances)
  verification: {
    ial_target: 'IAL1' | 'IAL2' | 'IAL3';
    ial_achieved: 'IAL0' | 'IAL1' | 'IAL2' | 'IAL3'; // IAL0 = none yet
    method_chain: Array<{                // each rung of the ladder
      method: string;
      attempted_at: string;
      outcome: 'pass' | 'fail' | 'partial';
      operator_actor_id?: string;        // if a human-in-the-loop step
    }>;
    coppa_relationship_proof?: {         // COPPA-specific
      method: '16-cfr-312-5-b-2-i' | '16-cfr-312-5-b-2-ii' |
              '16-cfr-312-5-b-2-iii' | '16-cfr-312-5-b-2-iv';
      verified_at: string;
      operator_actor_id: string;
    };
  };

  // Fulfillment state (mutated as handlers run)
  fulfillment: {
    status: 'intake' | 'verifying' | 'scoping' | 'in-progress' |
             'awaiting-operator-confirm' | 'extended' | 'fulfilled' |
             'partially-fulfilled' | 'refused-unverified' |
             'refused-exempt' | 'closed';
    extension: { invoked: boolean; reason?: string; new_deadline_at?: string };
    per_right_results: Array<{
      right: string;
      handler_outcome: 'completed' | 'partially-completed' |
                       'exempt-claimed' | 'not-applicable';
      exempt_subsections?: string[];     // e.g. ['ccpa-1798-105-d-2']
      operator_justification?: string;
    }>;
    deliverable_paths: string[];         // absolute paths to emitted artifacts
    delivered_to_subject_at?: string;    // operator-confirmed
    delivery_channel?: 'email' | 'secure-portal' | 'postal-mail' | 'in-person';
  };
}
```

```typescript
// Per-datastore subject-data probe — produced by dsar-fulfillment.ts
// during the scoping phase. One record per (datastore, subject) pair
// that the per-right handler iterates.
interface DsarDatastoreProbe {
  request_id: string;
  datastore_id: string;                  // matches U.U2 manifest
  probe_at: string;
  query_method:                          // how we asked the datastore
    'sql-select' | 'api-list' | 'log-search' | 'manual-attestation';
  records_matched: number;
  match_identifiers: string[];           // primary keys of matching records (encrypted-at-rest)
  data_categories_present:               // populated from U.U1 classification
    Array<'identifier' | 'commercial' | 'biometric' | 'internet-activity' |
          'geolocation' | 'sensory' | 'professional' | 'education' |
          'inferences' | 'sensitive-personal-info'>;
  retention_basis: string;               // from U.U2 datastore manifest
  exemption_candidates: string[];        // CCPA §1798.105(d)(1..9) subsection ids that may apply
}
```

## 5. Outputs

### 5.1 `out/dsar/<request_id>/audit-envelope.json` — the signed master record

Canonical JSON (RFC 8785) — every signed envelope in this corpus is
canonicalised before signing.

```json
{
  "schema_version": "u-u3.audit-envelope.v1",
  "schema_uri": "https://fedpy.dev/schemas/u-u3-audit-envelope-v1.json",
  "request_id": "01J<ulid>",
  "intake_at": "2026-06-07T09:00:00-04:00",
  "intake_channel": "web-form",
  "applicable_frameworks": ["ccpa", "cpra", "gdpr-eu"],
  "applicable_datastores": ["pgsql-prod-users", "s3-raw-events", "..."],
  "deadlines": {
    "ccpa_at": "2026-07-22T09:00:00-04:00",
    "gdpr_at": "2026-07-07T09:00:00-04:00",
    "earliest_at": "2026-07-07T09:00:00-04:00",
    "extended": false
  },
  "rights_requested": ["access", "deletion"],
  "verification": {
    "ial_target": "IAL2",
    "ial_achieved": "IAL2",
    "method_chain": [
      { "method": "account-credential-challenge", "attempted_at": "2026-06-07T09:01:13-04:00", "outcome": "pass" },
      { "method": "email-verification-link", "attempted_at": "2026-06-07T09:03:42-04:00", "outcome": "pass" }
    ]
  },
  "per_right_results": [
    { "right": "access", "handler_outcome": "completed",
      "deliverable_paths": ["out/dsar/<request_id>/portable-export-bundle.zip"] },
    { "right": "deletion", "handler_outcome": "partially-completed",
      "exempt_subsections": ["ccpa-1798-105-d-2"],
      "operator_justification": "Account holds open fraud investigation ticket #FR-2143; deletion would impair §1798.105(d)(2) security-incident response." }
  ],
  "operator_signoff": {
    "actor_id": "u-priv-officer-001",
    "actor_name": "(operator-supplied)",
    "actor_title": "Privacy Officer",
    "signed_off_at": "2026-07-05T16:18:00-04:00"
  },
  "delivery": {
    "delivered_to_subject_at": "2026-07-05T17:02:00-04:00",
    "channel": "secure-portal",
    "subject_acknowledgement_ref": "(operator-pasted)"
  },
  "envelope_signature": {
    "algorithm": "ed25519",
    "signing_key_version": "v3",
    "signature_b64": "(base64 ed25519 signature over canonical JSON minus this block)"
  },
  "rfc3161_timestamp": {
    "tsa_url": "(operator-configured)",
    "token_b64": "(rfc3161 token over the envelope_signature)"
  }
}
```

### 5.2 `out/dsar/<request_id>/portable-export-bundle.zip` — access/portability deliverable

ZIP layout:

```
portable-export-bundle.zip
├── manifest.json                # bundle index + per-file SHA-256
├── README.txt                   # plain-language guide to the contents
├── article-15-1-a-purposes.json # GDPR 15(1)(a) blocks
├── article-15-1-b-categories.json
├── article-15-1-c-recipients.json
├── article-15-1-d-retention.json
├── article-15-1-e-rights-notice.txt
├── article-15-1-f-complaint-notice.txt
├── article-15-1-g-sources.json
├── article-15-1-h-automated-decision-making.json  # from LOOP-O.O3 if applicable
├── ccpa-1798-110-categories-collected.json
├── ccpa-1798-115-categories-disclosed.json
├── per-datastore/<datastore_id>.json # one file per datastore, subject's records
└── per-datastore/<datastore_id>.csv  # CSV mirror for portability
```

### 5.3 `out/dsar/<request_id>/deletion-receipt.pdf` — deletion deliverable

Operator-signable PDF; includes the per-record deletion log, the
per-record exemption claims (with §1798.105(d)(N) subsection cited
inline), and the operator's signature line. Generated by
`dsar-export-bundler.ts::renderDeletionReceiptPdf(...)`. The PDF is
NOT auto-signed (REO Rule 4); the operator hand-signs before delivery.

### 5.4 `out/dsar/<request_id>/extension-notice.json` (conditional)

Emitted when the operator opts into the 45-day (CCPA) or 2-month
(GDPR) extension. The notice is bundled into a `.txt` for the subject
and a signed JSON envelope for the audit trail. Notice MUST be
delivered within the original-window deadline.

### 5.5 `out/dsar/<request_id>/refusal-notice.json` (conditional)

Emitted when verification fails after the ladder exhausts (per
§1798.140(ag) operator's right of refusal; GDPR Art. 11(2) excess-
information exclusion). Cites the specific subsection.

## 6. Algorithm / Steps

**Phase A — Intake (synchronous, in `tracker/server/routes/dsar.ts`)**:

1. Receive `POST /api/dsar/intake` (or CSV row, or email-relay webhook).
2. Generate `request_id` (ULID); set `intake_at` to server clock.
3. Validate the payload against the Ajv schema for `DsarIntakeRequest`.
4. Compute `applicable_frameworks` from
   `claimed_identity.jurisdictional_self_assertion` and U.U2's
   applicability matrix (e.g. country=US + state=CA ⇒ CCPA + CPRA;
   country in EU-27 ⇒ GDPR-EU; country=GB ⇒ GDPR-UK).
5. Compute `deadline_ccpa_at = intake_at + 45 calendar days` if CCPA
   applicable; null otherwise.
6. Compute `deadline_gdpr_at` per Reg 1182/71 Art 3(2)(c) if GDPR-EU or
   GDPR-UK applicable; null otherwise. The clock module
   (`dsar-deadline-clock.ts`) implements the same-numbered-day-of-next-
   month rule plus the rollback-to-last-day-of-month rule.
7. Compute `earliest_deadline_at = min(non-null deadlines)`.
8. Persist the row into `dsar_requests` (migration §7).
9. Look up applicable datastores via U.U2 manifest.
10. Acknowledge intake to the subject (operator pre-configures the
    acknowledgement template in `dsar-config.yaml`); record the
    acknowledgement in the audit envelope.
11. Emit `coverage:dsar-intake:received:1` to the orchestrator log.

**Phase B — Identity verification (asynchronous, in
`dsar-identity-verifier.ts`)**:

1. Read `verification.ial_target` from `dsar-identity-policy.yaml`.
2. Run the verifier ladder in order — e.g. for IAL2:
   (a) account-credential-challenge (if subject has an account);
   (b) email-verification-link (one-time code to claimed email);
   (c) phone-OTP (one-time code to claimed phone);
   (d) government-ID-hash-match (operator uploads ID image, hash
       compared to stored hash).
3. Each rung records to `verification.method_chain[]`.
4. If ANY rung returns `pass` AND the cumulative evidence meets the IAL
   floor, set `ial_achieved` and advance to Phase C.
5. If the ladder exhausts without reaching the floor:
   - For CCPA: emit `refusal-notice.json` citing §1798.140(ag); set
     `fulfillment.status = 'refused-unverified'`.
   - For GDPR: emit `refusal-notice.json` citing Art. 11(2); same
     status.
6. The verifier MUST NOT request additional data beyond what the
   ladder rung requires (Art. 12(6) excess-information prohibition).

**Phase C — Scoping (in `dsar-fulfillment.ts::scope(...)`)**:

1. For each `applicable_datastores[]` entry, dispatch a probe
   (`DsarDatastoreProbe`) — SQL select, API list, log search, or
   manual-attestation form.
2. The probe queries by the subject's verified identifiers (NOT the
   pre-verification claimed identifiers).
3. Each probe records `records_matched` and per-record
   `data_categories_present` (from U.U1 classification).
4. If a datastore returns >0 matches but the operator's exemption
   policy (`dsar-config.yaml`) flags the datastore as exempt for a
   given right, the probe records `exemption_candidates[]` for
   operator review.

**Phase D — Per-right handler dispatch (in
`dsar-fulfillment.ts::handle*(...)`)**:

For each `rights_requested[]`:

- **access / portability**:
  `dsar-export-bundler.ts::buildPortableExport(request, probes)` →
  emits `portable-export-bundle.zip`. Cross-jurisdictional bundle
  includes both GDPR Art. 15(1)(a)–(h) blocks AND CCPA §1798.110 +
  §1798.115 categorical disclosures.

- **deletion**:
  Two-phase confirmation: phase 1 prompts the operator to claim
  exemptions (`exemption_candidates[]` from Phase C) — operator may
  accept the candidate, reject it (forces deletion), or supply a
  fresh exemption code with justification. Phase 2 executes the
  deletion via the U.U2 datastore manifest's `delete_endpoint`
  configuration. Each per-record outcome is logged. The
  `deletion-receipt.pdf` is rendered with the per-record table.

- **correction**:
  `correction_payload[]` is validated against U.U1's allowed-edit
  schema for each `target_field`; if the proposed value violates a
  constraint the right is partially-fulfilled with a per-field error
  list. Accepted corrections are applied via the datastore's
  `update_endpoint`. The audit envelope records the before/after
  hashes.

- **opt-out (sale / share / targeted advertising)**:
  Writes a row to the `dsar_optout_registry` table; downstream
  marketing systems consume this registry (out of scope for this
  slice — see U.U4 for downstream propagation).

- **COPPA parental review/deletion**:
  Same as the adult equivalents, but Phase B uses the
  `coppa_relationship_proof` verifier (16 CFR §312.5(b)(2) methods).

**Phase E — Operator review + extension (in tracker UI status pane)**:

1. The tracker UI surfaces the request with the per-right results.
2. Operator may invoke the single 45-day CCPA extension OR the 2-month
   GDPR extension (or both if both frameworks apply). Each extension
   requires a free-text justification (Art. 12(3) GDPR; §1798.130(a)(2)
   CCPA). On opt-in, emit `extension-notice.json` AND deliver the
   notice to the subject within the original window.
3. Operator marks the request `awaiting-operator-confirm` when all
   per-right handlers complete.
4. Operator signs off; the audit envelope is sealed.

**Phase F — Sealing + delivery (in
`core/dsar-audit-envelope.ts::sealAndSign(...)`)**:

1. Canonicalise the envelope (RFC 8785).
2. Sign with the org's Ed25519 signing key (LOOP-A.A5).
3. Attach RFC 3161 timestamp token.
4. Bundle via LOOP-A.A4 submission bundler.
5. Surface the deliverable paths in the tracker UI; operator manually
   delivers to the subject; operator records
   `delivered_to_subject_at` + `delivery_channel` +
   `subject_acknowledgement_ref` in the tracker UI.
6. Mark `fulfillment.status = 'closed'`.

**Dedupe**: unique index on (request_id, right) ensures a re-run of
fulfillment is idempotent. The intake-side dedupe is on
(claimed_identity.primary_identifier_value_hash, rights_requested,
12-month window) per §1798.130(a)(2)(B).

## 7. Files to create / modify

### Files to create

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dsar-intake.ts`
   — payload validation, framework computation, deadline-clock entry
   point, intake-side persistence, dedupe-throttle check.
2. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dsar-fulfillment.ts`
   — per-right handler dispatch, scoping orchestration, audit-envelope
   composition, sealing/signing entry.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dsar-identity-verifier.ts`
   — IAL ladder runner, COPPA parent-of-minor verifier, refusal-notice
   emitter on ladder exhaustion.
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dsar-export-bundler.ts`
   — portable-export `.zip` composer (Art. 15(1)(a)–(h) blocks + CCPA
   §1798.110 + §1798.115); deletion-receipt `.pdf` renderer;
   correction-log emitter.
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dsar-deadline-clock.ts`
   — CCPA 45-calendar-day computation, GDPR 1-month per Reg 1182/71
   Art 3(2)(c), extension recomputation, T-7/T-3/T-0 notification
   scheduling.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/0050_dsar_requests.sql`
   — `dsar_requests` table + `dsar_optout_registry` + `dsar_audit_log`.
7. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/dsar.ts`
   — REST endpoints: `POST /api/dsar/intake`, `GET /api/dsar/:id`,
   `POST /api/dsar/:id/verify`, `POST /api/dsar/:id/extension`,
   `POST /api/dsar/:id/operator-signoff`,
   `POST /api/dsar/:id/mark-delivered`.
8. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/dsar-status-pane.tsx`
   — operator-facing UI; countdown timer to earliest deadline; per-right
   progress; extension button; exemption-claim form; sign-off button.
9. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/dsar-intake.test.ts`
   — intake-path tests (T1–T8 below).
10. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/dsar-fulfillment.test.ts`
    — fulfillment-path tests (T9–T18 below).

### Files to extend

11. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
    — new flag `--dsar-workflow` + env
    `CLOUD_EVIDENCE_DSAR_WORKFLOW`; runs AFTER U.U2; passes outputs to
    LOOP-A.A4 bundler.
12. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
    — `WELL_KNOWN` adds DSAR audit envelope as a bundled artifact role.
13. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`
    — extend with `dsar_workflow_coverage` section.
14. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/notify.ts`
    — extend with DSAR T-7/T-3/T-0 notification templates.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|----|----------|--------------|----------|------------|
| T1 | Intake from CA US resident exercising access + deletion; both CCPA + CPRA apply; deadlines computed | `tests/fixtures/dsar/intake-ca-access-delete.json` | `applicable_frameworks=['ccpa','cpra']`; `deadline_ccpa_at = intake_at + 45 calendar days`; `deadline_gdpr_at=null`; `earliest_deadline_at = deadline_ccpa_at` | `dsar-intake.test.ts` ISO8601 exact-match assertion |
| T2 | Intake from EU (DE) resident exercising access; GDPR-EU applies; deadline per Reg 1182/71 Art 3(2)(c) | `tests/fixtures/dsar/intake-de-access.json` (intake_at = 2026-01-15) | `deadline_gdpr_at = 2026-02-15T<same time>` | clock.test asserts same-numbered-day-of-next-month |
| T3 | Intake on Jan 31 from UK resident; Feb has no 31st; deadline rolls back to Feb 28 | `tests/fixtures/dsar/intake-uk-jan31.json` (intake_at = 2026-01-31) | `deadline_gdpr_at = 2026-02-28T<same time>` | clock.test asserts rollback-to-last-day rule |
| T4 | Intake on Jan 31 in a leap year (2028); rolls to Feb 29 | `tests/fixtures/dsar/intake-uk-jan31-leap.json` (intake_at = 2028-01-31) | `deadline_gdpr_at = 2028-02-29T<same time>` | clock.test leap-year branch |
| T5 | Dual-jurisdiction subject (CA US resident AND EU/DE citizen exercising under GDPR via subject statement); both clocks apply | `tests/fixtures/dsar/intake-dual-ca-de.json` | Both `deadline_ccpa_at` and `deadline_gdpr_at` set; `earliest_at = min(...)` | dual-clock branch coverage |
| T6 | Twice-in-12-months throttle (§1798.130(a)(2)(B)) — second access-only request from same identifier rejected | `tests/fixtures/dsar/intake-throttle-second.json` + pre-seeded DB row from 90 days ago | API returns 429 + body cites §1798.130(a)(2)(B); no DB row inserted | intake throttle test |
| T7 | COPPA parental request — `rights_requested = ['coppa-parental-review']`; intake creates a request with COPPA framework branch | `tests/fixtures/dsar/intake-coppa-parental.json` | `applicable_frameworks=['coppa']`; verifier path = COPPA ladder | COPPA branch coverage |
| T8 | Ajv schema rejects malformed intake (missing `claimed_identity`) | `tests/fixtures/dsar/intake-malformed.json` | API returns 400 + Ajv-derived error array | schema enforcement |
| T9 | IAL2 verifier ladder: account-credential pass + email-link pass → `ial_achieved='IAL2'`; advances to scoping | `tests/fixtures/dsar/verify-ial2-pass.json` | `verification.method_chain` length=2 with both `pass`; `fulfillment.status='scoping'` | verifier test |
| T10 | IAL2 verifier ladder exhausts (no rung passes) → emits `refusal-notice.json` citing §1798.140(ag) | `tests/fixtures/dsar/verify-ial2-fail.json` | `fulfillment.status='refused-unverified'`; `refusal-notice.json` exists with the verbatim §1798.140(ag) citation | refusal-path test |
| T11 | Excess-information prohibition (Art. 12(6)) — verifier MUST NOT request a government ID for an IAL1-target request | `tests/fixtures/dsar/verify-ial1-target.json` | Verifier ladder includes only IAL1 rungs (self-assertion); no IAL2 rung attempted | Art. 12(6) compliance test |
| T12 | Scoping probe — subject has records in 3 datastores; one datastore flagged for §1798.105(d)(2) exemption candidate | `tests/fixtures/dsar/scope-3-stores.json` | 3 `DsarDatastoreProbe` records; one with `exemption_candidates=['ccpa-1798-105-d-2']` | scoping test |
| T13 | Deletion handler — operator accepts exemption candidate → record NOT deleted; envelope carries `exemption_disclosure` block | `tests/fixtures/dsar/delete-with-exemption.json` | 1 record marked `exempt-claimed`; `audit-envelope.json` cites §1798.105(d)(2) verbatim | deletion+exemption test |
| T14 | Portable export bundle has all 8 GDPR Art. 15(1)(a)–(h) blocks + both CCPA §1798.110 + §1798.115 categories | `tests/fixtures/dsar/access-eu-ca-dual.json` | `portable-export-bundle.zip` unzips to all 10 expected files | bundle-composition test |
| T15 | Audit envelope JSON validates against Ajv schema `u-u3.audit-envelope.v1` | (any fixture) | `ajv.validate(schema, envelope)` returns true | schema-enforcement test |
| T16 | Audit envelope Ed25519 signature verifies against configured public key | (any fixture) | `verifyEnvelope(env, pubkey)` returns true | reuses LOOP-A.A5 sign-test harness |
| T17 | Extension path: operator opts in to 2-month GDPR extension at day 25; `extension-notice.json` emitted; new deadline = original + 2 months per Reg 1182/71 | `tests/fixtures/dsar/extension-gdpr.json` | `fulfillment.extension.invoked=true`; `new_deadline_at = original + 2 months`; extension-notice exists; notice delivery within original window | extension-path test |
| T18 | T-7-day notification scheduled correctly (row in `scheduled_notifications`) | (any fixture with deadline) | `SELECT fire_at FROM scheduled_notifications WHERE request_id=...` returns `earliest_deadline_at - 7 days` | notification-scheduling test |

Total: 18 tests (3 above the §8 floor of 15 — extra coverage for the
clock arithmetic, the IAL ladder, the exemption-handler branch, and
the extension path). Test coverage hits all major code paths:
clock arithmetic (T1–T5), throttle (T6), COPPA branch (T7), schema
enforcement (T8, T15), verifier ladder (T9–T11), scoping (T12),
per-right handlers (T13–T14), signing (T16), extension (T17),
notification (T18).

## 9. Risks

### Risk 1 — CCPA "calendar day" vs. GDPR "month" calendar collision

**Cause.** A dual-jurisdiction subject (CA US resident exercising
rights AND an EU resident under GDPR — e.g. a dual-national or a
recent emigrant) creates two clocks that do not align. The 45 calendar
days from a Jan-receipt expires ~Feb 14; the 1-month GDPR deadline
expires Feb 15. The operator must hit the **earlier** deadline to be
compliant with both; missing CCPA's 45-day clock by even one hour is a
violation regardless of GDPR's later expiry.

**Likelihood.** Moderate (the dual-citizenship case is rare per
request, but at scale the CSP will see them).

**Impact.** High — missing either deadline is a per-request violation
under each regime ($7,500/intentional violation CCPA + administrative
fines up to 20M EUR or 4% of global turnover GDPR).

**Mitigation.** `earliest_deadline_at` is the single operational
deadline shown in the tracker UI. The countdown timer always points to
the earlier of the two clocks. Tests T1+T2+T5 cover the dual case.
Operator's Privacy Officer receives the T-7-day notice on the
earliest clock, not the later one.

### Risk 2 — Same-numbered-day-of-next-month edge cases (Jan 31, leap year, DST)

**Cause.** Reg 1182/71 Art 3(2)(c) says "if the day on which it should
expire does not occur in the last month, the period shall end with
the expiry of the last hour of the last day of that month". A naive
"add 30 days" implementation diverges from the regulation on Jan 31
(→ Feb 28 or 29, not Mar 2/3), Mar 31 (→ Apr 30, not Apr 30 either —
it happens to be the same here), and May 31 (→ Jun 30). DST
transitions also affect the "last hour" semantics.

**Likelihood.** Twice a year for DST; ~12 times a year for end-of-
month receipts.

**Impact.** Moderate — a 1-day or 1-hour deadline miss may or may
not be a regulatory issue depending on how strictly the supervisory
authority interprets "one month"; the safe reading is strict.

**Mitigation.** The clock module uses ISO8601 timestamps with explicit
TZ designators and IANA tzdata (`@js-temporal/polyfill`). The
same-numbered-day rule is implemented as a single branching function;
tests T3+T4 cover Jan 31 → Feb 28 and the leap-year Feb 29 case.
DST transitions are tested for Europe/Berlin (last Sunday of March +
last Sunday of October).

### Risk 3 — Identity-verification under-rigor (under-IAL) leaks data to wrong subject

**Cause.** A weak verifier (IAL1 self-assertion for a high-risk
datastore) returns personal data to an attacker impersonating the
subject. This is itself a data-protection violation (Art. 5(1)(f)
GDPR integrity-and-confidentiality principle; CCPA §1798.150 private
right of action for unauthorized disclosure).

**Likelihood.** Low if the operator configures `dsar-identity-policy.yaml`
correctly; Moderate if defaults are accepted.

**Impact.** High — a single leak triggers breach-notification
obligations (LOOP-G + CIRCIA) plus statutory damages.

**Mitigation.** Default IAL is IAL2 (not IAL1). The orchestrator
refuses to run U.U3 if `dsar-identity-policy.yaml` declares IAL1 for
any datastore classified as containing special-category data under
GDPR Art. 9 or sensitive-personal-information under CPRA
§1798.140(ae). The verifier ladder is configured per-datastore-class,
not per-request — the highest IAL across all in-scope datastores wins.

### Risk 4 — Identity-verification over-rigor (over-IAL) violates Art. 12(6) excess-information prohibition

**Cause.** A verifier that requires government-ID for a self-asserted
IAL1 request (e.g. anonymous newsletter unsubscribe) collects more
identity data than is necessary, violating Art. 12(6) and
generating a fresh DSAR ("delete the ID you just collected").

**Likelihood.** Moderate (operators tend to over-collect to be safe).

**Impact.** Moderate — generates regulator complaint volume; the
collected ID itself is now subject to the same data-protection
regime and must be deleted.

**Mitigation.** Verifier ladder is gated by `ial_target`, not by
`ial_achieved` — the ladder STOPS at the target. Test T11 covers.
The collected verification artifacts are stored encrypted-at-rest
and auto-deleted 30 days after request closure (per
`dsar-identity-policy.yaml::verification_artifact_retention_days`,
default 30).

### Risk 5 — Operator forgets to deliver the extension notice within the original window

**Cause.** Both CCPA §1798.130(a)(2)(A) and GDPR Art. 12(3) require
**notice to the subject** of the extension within the original-window
deadline. The operator may invoke the extension internally and miss
the proactive notice. The clock does NOT toll; the extension is
unilaterally invalid if the notice is late.

**Likelihood.** Moderate (easy to overlook).

**Impact.** High — the extension is null; the original deadline
applies; the operator is now retroactively over the deadline.

**Mitigation.** Operator extension invocation in the tracker UI is a
TWO-step transaction: (1) operator clicks "extend", (2) operator
clicks "deliver extension notice" AND records the delivery
acknowledgement reference. The audit envelope's
`fulfillment.extension.invoked` flag is gated on (2) completing. If
(2) does not complete before the original deadline, the UI banner
turns red with "Extension invalid — notice not delivered" and the
deadline reverts to the original.

### Risk 6 — Deletion exemption-claim misuse (operator over-claims)

**Cause.** The §1798.105(d)(1..9) exemptions are operator-asserted;
an operator may over-claim (e.g. invoking (d)(2) "security incident"
to retain data with no actual incident) to avoid the cost of
deletion. A 3PAO audit or AG investigation may find the claim
unsupported.

**Likelihood.** Low if the operator is well-governed; Moderate at
scale.

**Impact.** High — each unsupported claim is a per-record violation
+ a credibility blow to the CSP's privacy posture.

**Mitigation.** Each exemption claim REQUIRES a free-text
justification + an evidence-link field (URL or ticket id pointing to
the supporting record). The audit envelope serializes both. A
periodic LOOP-N adversarial review (out-of-scope for this slice but
called out in U.U3's "open questions") samples exemption claims for
plausibility. The tracker UI surfaces a "claim rate" metric per
operator-actor — anomalously high claim rates trigger a Privacy
Officer review.

### Risk 7 — Cross-datastore consistency (delete-from-A-but-not-B)

**Cause.** A subject's data is spread across N datastores. The
deletion handler may succeed in datastore A and fail in datastore B
(e.g. B is offline). The audit envelope records the per-datastore
outcome but the operator may close the request as "fulfilled" when
it's actually "partially-fulfilled".

**Likelihood.** Moderate (rare per-request; common at scale).

**Impact.** High — undeleted records in B are now in violation of
the deletion right.

**Mitigation.** Phase D's per-right handler records per-datastore
outcomes individually. The audit envelope's
`fulfillment.per_right_results[].handler_outcome` is
`'partially-completed'` if ANY per-datastore outcome is `partial` or
`failed`. The fulfillment phase MUST be re-invoked after the failing
datastore returns to service; a `deletion-retry-queue` row is
inserted. The operator cannot close a `partially-completed` request
without explicit override (audit-logged).

### Risk 8 — Subject jurisdictional self-assertion is false (intentionally or by accident)

**Cause.** The subject self-asserts country/state at intake. If the
assertion is wrong (subject says "US-CA" but is actually EU resident)
the wrong framework set is applied — leading to wrong deadlines and
wrong content in the export bundle.

**Likelihood.** Moderate (subjects may not know which framework
applies).

**Impact.** Moderate — under-coverage (e.g. missing GDPR blocks in
the export) generates regulator complaints; over-coverage (extra
GDPR blocks) is benign.

**Mitigation.** U.U2's applicability matrix is **data-driven** — the
datastore-level applicability already encodes which datastores carry
GDPR-subject data, so even a self-asserted "US-CA" subject whose
records sit in an EU-applicable datastore triggers the GDPR branch.
The framework computation in Phase A union-aggregates the
self-asserted frameworks WITH the per-record applicability from
U.U2. Over-coverage is the default; under-coverage requires
explicit operator override (audit-logged).

## 10. Open questions

- **Q1 — UK GDPR enforcement-divergence in 2026.** Status:
  **REQUIRES-RESEARCH**. The Data (Use and Access) Bill 2025/26
  introduces UK-specific divergence from EU GDPR. Implementer to
  re-check the ICO's published guidance at the time of implementation
  for any 2026-effective changes to the one-month clock or the
  Article 12(6) verification carve-out.
- **Q2 — CPRA regulations §7060 verification-method specificity.**
  Status: **REQUIRES-RESEARCH**. The CCPA Regulations (CPRA-amended)
  §7060 enumerate "reasonable methods" for verification; the §7062
  high-risk-data heightened verification is a regulator-published
  catalog. Implementer to re-check the latest regulations text.
- **Q3 — GDPR-style "without undue delay" semantics.** Status:
  **REQUIRES-OPERATOR-INPUT** (see §11). The Art. 12(3) text says
  "without undue delay and in any event within one month". A
  conservative operator may set an internal SLA shorter than the
  one-month maximum. Default is one month; operator may override.
- **Q4 — Subject's right to receive the data in machine-readable
  form vs. portable form.** Status: **REQUIRES-RESEARCH**. CCPA
  §1798.130(a)(2)(B) says "portable and ... readily useable" — JSON
  + CSV satisfy this. GDPR Art. 20 (right to data portability) adds
  "structured, commonly used and machine-readable format" — also
  satisfied. The risk is over-reading the requirement and
  attempting to provide every column in a CSV when the regulator
  expects a curated subset.
- **Q5 — Two-month GDPR extension vs. CCPA's single 45-day extension
  cap.** For a dual-jurisdiction subject, can the operator invoke
  both extensions? Likely yes (each clock is independent); the
  earliest of the two extended deadlines wins. REQUIRES-OPERATOR-INPUT
  to confirm with privacy counsel.
- **Q6 — COPPA verifier method retirement.** The FTC's COPPA Rule
  amendments (2024) added new approved verifier methods (knowledge-
  based authentication; facial-recognition-with-government-ID). The
  16 CFR §312.5(b)(2) list may diverge from operator's currently
  implemented method. Re-check FTC's published list at implementation
  time.

## 11. REQUIRES-OPERATOR-INPUT fields

| Field name | Type | Validator | UI location | Failure mode if missing |
|------------|------|-----------|-------------|--------------------------|
| `privacy_officer_email` | string (RFC 5322) | RFC 5322 syntax + MX-record check | Settings → Privacy → Privacy Officer | T-7/T-3 notifications fall back to the LOOP-A.A4 default notifier; banner: "Privacy Officer email missing — notifications suppressed". |
| `dsar_intake_acknowledgement_template` | string (Markdown) | template-engine syntax check | Settings → Privacy → Acknowledgement Template | Intake fails (operator must declare the acknowledgement text per §1798.130(a)(1)(B)). |
| `ial_target_per_datastore_class` | map<datastore_class, IAL1\|IAL2\|IAL3> | enum + datastore-class lookup | Settings → Privacy → Identity Verification | Default IAL2 for all classes; orchestrator refuses to run if any Art. 9 / sensitive-PI datastore declared IAL1. |
| `verification_artifact_retention_days` | integer (1..365) | range check | Settings → Privacy → Identity Verification | Default 30. |
| `dsar_exemption_policy_per_datastore` | map<datastore_id, exemption_subsection[]> | enum validator | Settings → Privacy → Datastore Exemptions | Default empty; no exemption candidates surfaced. |
| `extension_invocation_authorized_actors` | array of actor_ids | RBAC role lookup | Settings → Privacy → Authorization | Default = `privacy-officer`; orchestrator refuses extension if no actor with role. |
| `dsar_optout_registry_consumers` | array of webhook URLs | URL + HMAC-handshake test | Settings → Privacy → Opt-Out Propagation | Opt-out rows persist but downstream marketing systems are not notified; banner warning. |
| `subject_deliverable_channel_default` | enum: `secure-portal` \| `email` \| `postal-mail` | enum validator | Settings → Privacy → Delivery | Default `secure-portal`; operator may override per-request. |
| `ed25519_signing_key_ref` | string (KMS resource) | `core/sign.ts::testSign(key_ref)` | Settings → Compliance → Signing | Orchestrator refuses to run; exit code 2. |
| `dsar_audit_log_retention_years` | integer (≥3 per §1798.130(a)(7); ≥3 per Art. 30 GDPR) | range check | Settings → Privacy → Audit Retention | Default 6 (CCPA + GDPR safe-harbor union); cannot be set below 3. |
| `coppa_parental_verifier_method` | enum (16 CFR §312.5(b)(2)(i..iv)) | enum + per-method config validator | Settings → Privacy → COPPA | If COPPA framework applies and missing, orchestrator refuses COPPA path. |
| `intake_throttle_per_subject_per_12mo` | integer (default 2 per §1798.130(a)(2)(B)) | integer ≥ 1 | Settings → Privacy → Throttle | Default 2. |
| `dual_jurisdiction_clock_policy` | enum: `earliest-wins` \| `per-framework-track` | enum validator | Settings → Privacy → Dual Jurisdiction | Default `earliest-wins`; per-framework-track surfaces both countdowns separately. |
| `extension_default_justification_template` | string (Markdown) | template-engine syntax check | Settings → Privacy → Extension Template | Default empty; operator must type free-text at extension time. |
| `tsa_url` | string (URL) | URL + TSA-handshake test | Settings → Signing → Timestamp Authority | Default to LOOP-A.A5 org TSA; warn if missing. |
| `tracker_db_kms_data_key_ref` | string | KMS resource validator | Settings → Tracker → Encryption | Default to org's tracker DB encryption key; exit 2 in production if missing. |

Total: 16 fields. Of these, **5 are blocking** at startup
(`dsar_intake_acknowledgement_template`,
`ed25519_signing_key_ref`, `tracker_db_kms_data_key_ref`,
`coppa_parental_verifier_method` if COPPA applies,
`extension_invocation_authorized_actors`), **4 are soft-warning**
(notify/opt-out/TSA/privacy-officer), and **7 default** to safe
values if missing.

## 12. Implementation log

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-07 | wf-uvxyz | Specification authored via FedPy workflow | TBD | Self-contained per-slice doc proposed; LOOP-U-SPEC.md not yet authored — this doc carries enough verbatim citation depth to stand alone. Re-verify Reg 1182/71 Art 3(2)(c) wording against the EUR-Lex authoritative HTML before implementation. |

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
> ### Step 8 (U.U3-specific addendum)
> After the commit lands, append the U.U3 row to STATUS.md (status →
> done, commit hash, last_updated); update LOOP-U-SPEC.md status table
> (U.U3 row) — if LOOP-U-SPEC.md does not yet exist at completion time,
> create it with the U.U3 row pre-seeded and surface the gap to the
> next session; append a CHANGELOG entry (LOOP-U.U3 — DSAR Intake +
> Fulfillment Workflow); push to origin/main; verify with
> `git log --oneline -3`. Only THEN is U.U3 closed.

REO STANDARD (Rule 1–4) governs every line of production code described
in §7. No invented citations. Apache-2.0 clean-room.
