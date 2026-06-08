---
slice_id: V.V3
title: HIPAA Breach Notification Workflow (45 CFR §§164.400-414) — 60-day calendar-day clock + 4-factor §164.402(2) risk assessment + <500 vs ≥500 reporting path + BA-to-CE §164.410 notification
loop: V
status: proposed
commit: TBD
completed_date: —
depends_on:
  - V.V1                                # HIPAA Security Rule catalog (cited in breach narratives)
  - V.V2                                # HIPAA evidence emitter (4-factor envelopes reuse the V.V2 signer)
  - LOOP-G.G2                           # Incident communications procedures (parent incident record FK)
  - LOOP-M.M4                           # Privacy incident response (DPIA-linked breach metadata)
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing primitive
  - LOOP-A.A4                           # Submission-bundle pattern (HHS / media / BA-to-CE letter packets)
  - tracker DB                          # Append-only breach log lives in tracker schema
blocks: []
estimated_effort: medium (~6-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: true
condition: |
  CSP is acting as a HIPAA Covered Entity (CE) OR Business Associate (BA)
  per 45 CFR §164.502(e). The applicability predicate is
  `compliance.hipaa.role ∈ {covered-entity, business-associate}` in
  `config.yaml`. When the role is `none`, V.V3 is a no-op for the
  orchestrator run (exit 0 with skip log). Subcontractors of BAs are in
  scope because 45 CFR §160.103 defines them as BAs by extension.
trigger_flag: "--hipaa-breach-notification"
trigger_env: CLOUD_EVIDENCE_HIPAA_BREACH_NOTIFICATION
---

# V.V3 — HIPAA Breach Notification Workflow (45 CFR §§164.400-414)

> V.V3 is the **operational** slice for LOOP-V: it is the workflow
> that fires when a CSP discovers (or reasonably should have
> discovered) unauthorized acquisition, access, use, or disclosure of
> Unsecured Protected Health Information (Unsecured PHI). The slice
> turns a raw incident (typically opened in LOOP-G.G2) into a
> structured, signed, append-only breach record that drives THREE
> downstream notification paths — individual notice, HHS Secretary
> notice (annual vs contemporaneous depending on count), and (for ≥500
> in a single state/jurisdiction) media notice — plus the BA-to-CE
> notification that §164.410 imposes when the CSP is the BA. Every
> deadline is computed in **calendar days** (not business days), every
> 4-factor risk assessment is locked to the verbatim §164.402(2) text,
> every artifact is Ed25519-signed and RFC 3161 timestamped, and every
> record is append-only with a per-version hash chain so an HHS-OCR
> auditor can replay the operator's reasoning at any point in the
> incident lifecycle.

## 1. Mission

V.V3 implements the **HIPAA Breach Notification Rule** (45 CFR Part
164, Subpart D — §§164.400 through 164.414) as a deterministic,
signed, audit-defensible workflow inside the FedPy cloud-evidence
orchestrator. The slice covers the full breach lifecycle:

1. **Triage** — ingest an incoming incident (linked by foreign key
   to a LOOP-G.G2 `incident_records` row) and classify whether it
   touched **Unsecured PHI** as that term is defined at 45 CFR
   §164.402(1) and qualified by the HHS Guidance Specifying
   Technologies and Methodologies (74 FR 19006, 2009-04-27,
   reaffirmed by HHS in 2013).

2. **4-factor risk assessment** — when the incident touched
   Unsecured PHI, force the operator to complete the four-factor
   compromise-probability analysis prescribed by §164.402(2):
   nature/extent of PHI, identity of the unauthorized recipient,
   actual acquisition-or-viewing evidence, and extent of mitigation.
   A finding of "low probability of compromise" requires all four
   factors at `low` with non-empty narratives, an operator digital
   signature (WebAuthn/PIV), and survives append-only revision
   tracking.

3. **Clock arithmetic** — when the incident IS a Breach (i.e.
   §164.402(2) does not negate it), compute the three calendar-day
   clocks: (a) individual notification 60 days from discovery per
   §164.404(b); (b) HHS Secretary notification 60 days for ≥500
   individuals per §164.408(b) OR annual aggregate by 60 days after
   end of CY for <500 per §164.408(c); (c) media notice 60 days when
   ≥500 residents of a single state/jurisdiction per §164.406(b).

4. **BA-to-CE notification** — when the CSP is a BA, fire §164.410
   notification to every affected CE without unreasonable delay and
   in no case later than 60 calendar days after discovery, tracked
   against a tighter operator-configurable internal target (default
   30 days; configurable per-BAA down to 5 days when the CE's
   contract demands it).

5. **Artifact emission** — render the individual-notice letter
   (`.docx` OOXML zip-store), the HHS Secretary submission envelope
   (HHS portal does not accept machine submission — REO Rule 4 — so
   the artifact is a checklist + structured JSON the operator hand-
   keys into https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf),
   the media-notice press release, and the BA-to-CE notification.
   Every artifact carries a `provenance` block, Ed25519 detached
   signature, RFC 3161 timestamp token, and CHANGELOG entry.

6. **Append-only audit trail** — every operator action against a
   breach record (create, classify, edit 4-factor, mark notified)
   produces a new immutable `breach_log_versions` row with
   `prior_version_hash` forming a hash chain. The HHS-OCR audit
   defense is "show me every decision and who made it"; V.V3's
   schema makes that trivial.

V.V3 does **not** implement state-AG notifications (those overlay on
top of HIPAA via state breach-notification statutes; LOOP-U handles
state law). V.V3 does **not** auto-submit anything to HHS or to the
media — REO Rule 4 forbids automated submission to a federal portal.
V.V3 does **not** decide for the operator whether an event is a
breach; it computes the §164.402(2) framework and surfaces the
finding, but the human privacy officer is the decision-maker of
record and digitally signs the finding.

The slice is deterministic: a given (incident metadata, 4-factor
narrative payload, operator role, current-clock-time) tuple always
produces the same artifact bytes. Determinism is what makes the
append-only hash chain meaningful — any byte difference between
versions is a real operator change, not a non-deterministic
re-render.

## 2. Authoritative sources

Every URL accessed 2026-06-08. Verbatim quotes appear in Markdown
blockquotes. Where a live federal source returned a non-200 to
anonymous fetches, the operator mirrors the page to
`cloud-evidence/docs/sources/hipaa-breach/` and re-quotes verbatim
from the local copy. Every row in the V.V3 catalog tables and every
narrative line in an emitted artifact carries a `source_ref`
pointing at the mirror so a 3PAO can reconstruct the legal basis
without re-fetching from HHS.

### 2.1 45 CFR §164.402 — Definitions (the Breach + 4-factor exception)

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.402
(accessed 2026-06-08).

The Breach definition itself — §164.402:

> "Breach means the acquisition, access, use, or disclosure of
> protected health information in a manner not permitted under
> subpart E of this part which compromises the security or privacy
> of the protected health information."

The three categorical exclusions under §164.402(1) — these are
threshold filters that V.V3 evaluates BEFORE running the 4-factor
test:

> "(1) Breach excludes:
> (i) Any unintentional acquisition, access, or use of protected
> health information by a workforce member or person acting under the
> authority of a covered entity or a business associate, if such
> acquisition, access, or use was made in good faith and within the
> scope of authority and does not result in further use or
> disclosure in a manner not permitted under subpart E of this part.
> (ii) Any inadvertent disclosure by a person who is authorized to
> access protected health information at a covered entity or business
> associate to another person authorized to access protected health
> information at the same covered entity or business associate, or
> organized health care arrangement in which the covered entity
> participates, and the information received as a result of such
> disclosure is not further used or disclosed in a manner not
> permitted under subpart E of this part.
> (iii) A disclosure of protected health information where a covered
> entity or business associate has a good faith belief that an
> unauthorized person to whom such disclosure was made would not
> reasonably have been able to retain such information."

The **4-factor risk assessment** at §164.402(2) — this is the most
heavily cited paragraph in the entire LOOP-V corpus and is quoted
verbatim into every emitted 4-factor envelope:

> "(2) Except as provided in paragraph (1) of this definition, an
> acquisition, access, use, or disclosure of protected health
> information in a manner not permitted under subpart E is presumed
> to be a breach unless the covered entity or business associate, as
> applicable, demonstrates that there is a low probability that the
> protected health information has been compromised based on a risk
> assessment of at least the following factors:
> (i) The nature and extent of the protected health information
> involved, including the types of identifiers and the likelihood of
> re-identification;
> (ii) The unauthorized person who used the protected health
> information or to whom the disclosure was made;
> (iii) Whether the protected health information was actually
> acquired or viewed; and
> (iv) The extent to which the risk to the protected health
> information has been mitigated."

The §164.402(1) encryption Safe Harbor — defining "Unsecured":

> "Unsecured protected health information means protected health
> information that is not rendered unusable, unreadable, or
> indecipherable to unauthorized persons through the use of a
> technology or methodology specified by the Secretary in the
> guidance issued under section 13402(h)(2) of Public Law 111-5."

The HHS Guidance referenced is at 74 FR 19006 (2009-04-27) and
specifies NIST SP 800-111 (encryption at rest) + FIPS 140-2/140-3
validated cryptographic modules + NIST SP 800-52 Rev 2 (TLS) as the
qualifying technologies. V.V3 carries the §164.402(1) verbatim text
in every emitted envelope so the Safe Harbor claim path is
auditable.

### 2.2 45 CFR §164.404 — Notification to individuals

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.404
(accessed 2026-06-08).

§164.404(a)(1) — the trigger:

> "A covered entity shall, following the discovery of a breach of
> unsecured protected health information, notify each individual
> whose unsecured protected health information has been, or is
> reasonably believed by the covered entity to have been, accessed,
> acquired, used, or disclosed as a result of such breach."

§164.404(a)(2) — the discovery anchor (this is the moment the
60-day clock starts ticking; V.V3's clock arithmetic engine pins
to the operator-declared `discovered_at` timestamp and validates
it against `system_detection_at` to surface late anchors):

> "For purposes of paragraph (a)(1) of this section, §§ 164.406(a),
> and 164.408(a), a breach shall be treated as discovered by a
> covered entity as of the first day on which such breach is known
> to the covered entity, or, by exercising reasonable diligence,
> would have been known to the covered entity. A covered entity
> shall be deemed to have knowledge of a breach if such breach is
> known, or by exercising reasonable diligence would have been
> known, to any person, other than the person committing the breach,
> who is a workforce member or agent of the covered entity
> (determined in accordance with the federal common law of agency)."

§164.404(b) — the 60-calendar-day cap:

> "Except as provided in § 164.412, a covered entity shall provide
> the notification required by paragraph (a) of this section without
> unreasonable delay and in no case later than 60 calendar days
> after discovery of a breach."

The phrase "without unreasonable delay" is operationally important:
HHS has cited operators for waiting close to day 60 when remediation
was complete on day 5 (HHS Resolution Agreements; see §2.8 below).
V.V3 surfaces an `unreasonable_delay_warning` whenever the elapsed
time between `discovered_at` and `notified_at` exceeds 30 days and
forces the operator to populate an `unreasonable_delay_rationale`
narrative field.

§164.404(c)(1) — the **mandatory letter content** (every emitted
individual-notice letter MUST include these five elements):

> "The notification required by paragraph (a) of this section shall
> include, to the extent possible:
> (A) A brief description of what happened, including the date of the
> breach and the date of the discovery of the breach, if known;
> (B) A description of the types of unsecured protected health
> information that were involved in the breach (such as whether full
> name, social security number, date of birth, home address, account
> number, diagnosis, disability code, or other types of information
> were involved);
> (C) Any steps individuals should take to protect themselves from
> potential harm resulting from the breach;
> (D) A brief description of what the covered entity involved is
> doing to investigate the breach, to mitigate harm to individuals,
> and to protect against any further breaches; and
> (E) Contact procedures for individuals to ask questions or learn
> additional information, which shall include a toll-free telephone
> number, an e-mail address, Web site, or postal address."

V.V3's `hipaa-breach-letter-docx.ts` renderer hard-fails (throws
`HIPAALetterMissingRequiredElementError`) if any of the five §164.404(c)(1)
slots is empty. Tracker DB stores the five fields as separate
NOT NULL columns precisely so the constraint is enforced at the
database layer too.

### 2.3 45 CFR §164.406 — Notification to the media

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.406
(accessed 2026-06-08).

§164.406(a) — the ≥500-in-state trigger:

> "For a breach of unsecured protected health information involving
> more than 500 residents of a State or jurisdiction, a covered
> entity shall, following the discovery of the breach as provided in
> § 164.404(a)(2), notify prominent media outlets serving the State
> or jurisdiction."

§164.406(b) — the 60-day timing cap:

> "Except as provided in § 164.412, a covered entity shall provide
> the notification required by paragraph (a) of this section without
> unreasonable delay and in no case later than 60 calendar days
> after discovery of a breach."

§164.406(c) — content requirements (same five §164.404(c)(1)
elements):

> "The notification required by paragraph (a) of this section shall
> meet the requirements of § 164.404(c)."

The "500 residents of a State or jurisdiction" predicate is
**per-state**, not aggregate. A breach affecting 600 people split
across two states (300 in NY, 300 in CA) does NOT trigger media
notice under §164.406. A breach affecting 503 people all in NY DOES
trigger NY media notice. V.V3's clock engine computes media-notice
applicability by iterating per-state counts; the test corpus
T-V3-08 pins a multi-jurisdiction case (single incident, two states
each ≥500) where TWO media notices fire.

### 2.4 45 CFR §164.408 — Notification to the Secretary

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.408
(accessed 2026-06-08).

§164.408(a) — the universal HHS notification requirement:

> "A covered entity shall, following the discovery of a breach of
> unsecured protected health information as provided in §
> 164.404(a)(2), notify the Secretary."

§164.408(b) — the ≥500 contemporaneous-HHS rule:

> "For breaches of unsecured protected health information involving
> 500 or more individuals, a covered entity shall, except as
> provided in § 164.412, provide the notification required by
> paragraph (a) of this section contemporaneously with the
> notification required by § 164.404(a) and in the manner specified
> on the HHS Web site."

§164.408(c) — the <500 annual aggregate path:

> "For breaches of unsecured protected health information involving
> less than 500 individuals, a covered entity shall maintain a log
> or other documentation of such breaches and, not later than 60
> days after the end of each calendar year, provide the
> notification required by paragraph (a) of this section for
> breaches discovered during the preceding calendar year, in the
> manner specified on the HHS Web site."

V.V3's `core/hipaa-60day-clock.ts` engine branches on
`affected_individuals_count >= 500`:

- **≥500 path**: same 60-day deadline as individual notification;
  HHS notification submitted contemporaneously with the individual
  notifications via the HHS Breach Portal
  (https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf).

- **<500 path**: queue in the `breach_log` table; the annual
  scheduler emits a `hhs-annual-breach-submission-CYYYYY.json` +
  `.docx` packet on or before March 1 of the following calendar
  year. Tracker UI banner reminds at T-90/T-30/T-7 days.

### 2.5 45 CFR §164.410 — Notification by a business associate

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.410
(accessed 2026-06-08).

§164.410(a)(1) — the BA's trigger:

> "A business associate shall, following the discovery of a breach
> of unsecured protected health information, notify the covered
> entity of such breach."

§164.410(b) — the BA's 60-day cap (same calendar-day clock as the
individual notification, but the recipient is the CE, not the
patient):

> "Except as provided in § 164.412, a business associate shall
> provide the notification required by paragraph (a) of this section
> without unreasonable delay and in no case later than 60 calendar
> days after discovery of a breach."

§164.410(c) — content requirements for the BA-to-CE notification:

> "(1) The notification required by paragraph (a) of this section
> shall include, to the extent possible, the identification of each
> individual whose unsecured protected health information has been,
> or is reasonably believed by the business associate to have been,
> accessed, acquired, used, or disclosed during the breach.
> (2) A business associate shall provide the covered entity with any
> other available information that the covered entity is required to
> include in notification to the individual under § 164.404(c) at
> the time of the notification required by paragraph (a) of this
> section or promptly thereafter as information becomes available."

The clock interaction is critical: a BA who exhausts day 58 before
notifying the CE leaves the CE with only 2 days to notify
individuals (the CE's 60-day clock starts at CE-discovery, but
§164.404(a)(2) treats the CE as having knowledge "by exercising
reasonable diligence" — HHS treats BA-discovery as imputed CE
knowledge in many enforcement actions, so the CE's clock may
effectively start when the BA discovers, not when the CE is told).
V.V3 enforces an internal BA-to-CE target of 30 days by default,
configurable per-BAA down to 5 days.

### 2.6 45 CFR §164.412 — Law enforcement delay

URL: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.412
(accessed 2026-06-08).

> "If a law enforcement official states to a covered entity or
> business associate that a notification, notice, or posting required
> under this subpart would impede a criminal investigation or cause
> damage to national security, a covered entity or business
> associate shall:
> (a) If the statement is in writing and specifies the time for
> which a delay is required, delay such notification, notice, or
> posting for the time period specified by the official; or
> (b) If the statement is made orally, document the statement,
> including the identity of the official making the statement, and
> delay the notification, notice, or posting temporarily and no
> longer than 30 days from the date of the oral statement, unless a
> written statement as described in paragraph (a) of this section is
> submitted during that time."

V.V3's clock engine supports a typed LE-delay attestation in the
`breach_log` table: `le_delay_kind: enum('written','oral','none')`,
`le_delay_official_identity: text`, `le_delay_received_at:
timestamptz`, `le_delay_expires_at: timestamptz`. The clock pauses
between `le_delay_received_at` and `le_delay_expires_at`. Tracker
UI surfaces the delay countdown alongside the original clock.

### 2.7 HITECH Act §13402 — Statutory basis (42 U.S.C. §17932)

URL: https://www.govinfo.gov/content/pkg/PLAW-111publ5/html/PLAW-111publ5.htm
(accessed 2026-06-08). The HITECH Act §13402 is the statutory
authority HHS implemented in 45 CFR §§164.400-414. The relevant
text from the statute itself:

> "Notification in the case of breach.
> (a) IN GENERAL.—A covered entity that accesses, maintains,
> retains, modifies, records, stores, destroys, or otherwise holds,
> uses, or discloses unsecured protected health information (as
> defined in subsection (h)(1)) shall, in the case of a breach of
> such information that is discovered by the covered entity, notify
> each individual whose unsecured protected health information has
> been, or is reasonably believed by the covered entity to have
> been, accessed, acquired, or disclosed as a result of such
> breach."

> "(b) NOTIFICATION OF COVERED ENTITY BY BUSINESS ASSOCIATE.—A
> business associate of a covered entity that accesses, maintains,
> retains, modifies, records, stores, destroys, or otherwise holds,
> uses, or discloses unsecured protected health information shall,
> following the discovery of a breach of such information, notify
> the covered entity of such breach. Such notice shall include the
> identification of each individual whose unsecured protected health
> information has been, or is reasonably believed to have been,
> accessed, acquired, or disclosed during such breach."

> "(d) TIMELINESS OF NOTIFICATION.—
> (1) IN GENERAL.—Subject to subsection (g), all notifications
> required under this section shall be made without unreasonable
> delay and in no case later than 60 calendar days after the
> discovery of a breach by the covered entity involved (or business
> associate involved in the case of a notification required under
> subsection (b))."

The "60 calendar days" anchor in the statute is what makes the
HIPAA clock arithmetic distinct from the CIRCIA 72-hour clock (66
hours of which can be weekend) and the FAR §889 1-business-day
clock — V.V3's clock engine MUST NOT subtract weekends/holidays.

### 2.8 HHS OCR Breach Notification Sample Letter guidance

URL: https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html
(accessed 2026-06-08; operator mirrors to
`docs/sources/hipaa-breach/hhs-breach-notification-landing-2026-06-08.html`).

> "If a breach of unsecured protected health information affects 500
> or more individuals, a covered entity must notify a prominent media
> outlet serving the State or jurisdiction. Covered entities will
> likewise provide these notifications without unreasonable delay
> but in no case later than 60 days following the discovery of a
> breach and must include the same information required for the
> individual notice."

> "In addition to notifying affected individuals and the media (where
> appropriate), covered entities must notify the Secretary of
> breaches of unsecured protected health information. Covered
> entities will notify the Secretary by visiting the HHS web site
> and filling out and electronically submitting a breach report form.
> If a breach affects 500 or more individuals, covered entities must
> notify the Secretary without unreasonable delay and in no case
> later than 60 days following a breach. If, however, a breach
> affects fewer than 500 individuals, the covered entity may notify
> the Secretary of such breaches on an annual basis."

V.V3's `hipaa-hhs-secretary-submitter.ts` produces a structured
JSON checklist matching the field shape of the HHS Breach Portal
wizard at https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf —
the operator hand-keys the fields, ticks each checklist item, and
the artifact captures the submission receipt confirmation number
back into the tracker DB. Per REO Rule 4 we never auto-submit to
the federal portal.

### 2.9 HHS OCR Annual Report to Congress on Breaches of Unsecured PHI

URL: https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/reports-congress/index.html
(accessed 2026-06-08).

> "The Secretary shall prepare and submit to the appropriate
> committees of Congress an annual report regarding the breaches for
> which notice was provided to the Secretary under this section."

The most recent published Annual Report to Congress (covering
calendar year breaches) is what V.V3 uses to calibrate its
`affected_individuals_count` distribution test (T-V3-13) and the
historical median time-to-notification metric surfaced in the
tracker dashboard. The report URL is captured in the V.V3 config
as the `historical_baseline_source` and refreshed annually.

### 2.10 HHS OCR Breach Portal ("Wall of Shame")

URL: https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf
(accessed 2026-06-08).

> "As required by section 13402(e)(4) of the HITECH Act, the
> Secretary must post a list of breaches of unsecured protected
> health information affecting 500 or more individuals."

V.V3 emits a one-line summary into the operator runbook reminding
that successful ≥500 HHS submissions become publicly listed on the
Breach Portal within ~7 days of submission and persist
indefinitely. The runbook also documents the operator's right to
request post-investigation updates to the portal entry (resolution
notes, corrective-action description) per HHS guidance.

### 2.11 NIST SP 800-66 Rev 2 §3.4 — Implementing the Breach Notification Rule

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf
(accessed 2026-06-08; operator mirrors to
`docs/sources/NIST.SP.800-66r2.pdf`).

NIST SP 800-66 Rev 2 §3.4 references the Breach Notification Rule
as a cross-rule integration point — the Security Rule's
§164.308(a)(6) Security Incident Procedures must include breach
notification handling. V.V3 reads §3.4's guidance into the operator
runbook as supplemental implementation context. The catalog row
captured by V.V1 includes the `nist_800_66_breach_rule_alignment`
flag for cross-reference.

### 2.12 HHS Sample Business Associate Agreement Provisions

URL: https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html
(accessed 2026-06-08).

> "Notwithstanding the above, business associate may use or
> disclose protected health information to report violations of law
> to appropriate Federal and State authorities, consistent with §
> 164.502(j)(1)."

The Sample BAA Provisions include the §164.410 notification clause
that every post-Omnibus (post-2013) BAA must contain. V.V3's
BA-to-CE notification renderer cross-references the operator's
executed BAA (sourced from V.V1's BAA registry) to confirm the
contractual notification-deadline parameter matches what V.V3 is
enforcing internally; mismatches surface a `baa-clock-mismatch`
diagnostic for legal review.

## 3. Scope

### 3.1 In scope

- **Triage**: classify an incoming LOOP-G.G2 incident as Breach /
  Not-Breach / Pending-4-factor against §164.402(1) categorical
  exclusions and the §164.402(1) encryption Safe Harbor.
- **4-factor risk assessment**: structured operator input against
  the verbatim §164.402(2) factors; append-only versioning; digital
  signature (WebAuthn/PIV) at finalization.
- **60-day calendar-day clock arithmetic** for individual (§164.404),
  HHS Secretary (§164.408), media (§164.406), and BA-to-CE
  (§164.410) deadlines. LE-delay (§164.412) clock pause.
- **<500 vs ≥500 branching**: annual aggregate HHS submission for
  <500; contemporaneous HHS submission for ≥500.
- **Multi-state media notice**: per-state count evaluation against
  the §164.406(a) 500-residents-of-a-State threshold.
- **Individual-notice letter** (`.docx` OOXML zip-store, REO-compliant
  templating that hard-fails on missing §164.404(c)(1) elements).
- **HHS Secretary submission packet** (structured JSON checklist
  matching HHS Breach Portal wizard fields; manual operator submit
  per REO Rule 4).
- **Media-notice press release** (.docx with §164.406(c) =
  §164.404(c)(1) content requirements).
- **BA-to-CE notification packet** (.docx + structured JSON with
  §164.410(c) identification list).
- **Append-only `breach_log` + `breach_log_versions` schema** with
  hash chain for HHS-OCR audit defense.
- **Ed25519 + RFC 3161 signing** on every artifact + every version
  row.
- **Provenance block** on every emitted artifact citing V.V1
  catalog SHA-256 + this V.V3 source mirror set.
- **Tracker UI**: status pane showing the four clocks side-by-side,
  the 4-factor matrix view, the version history with hash-chain
  visualization.

### 3.2 Out of scope (NOT in V.V3)

- **State-AG / state-breach-law notification** — overlays on top of
  HIPAA per state-specific statutes; handled in LOOP-U.U4 (privacy
  incident response routing) and the `data/state-breach-laws.json`
  registry maintained there. V.V3 emits a `state-law-overlay-required`
  diagnostic when ≥500 in a state with stricter clock; LOOP-U.U4
  consumes and routes.
- **Auto-submission to HHS portal, media outlets, or CE email
  systems** — REO Rule 4 forbids automated federal submission.
  V.V3 prepares and signs the artifacts; the operator submits
  manually and records confirmation numbers back into the tracker.
- **De-identification analysis** — handled in V.V4 (PHI tagger /
  ePHI inventory). V.V3 consumes V.V4's output to compute
  `affected_individuals_count` but does not itself decide whether
  a dataset is identified PHI.
- **Workforce training records** — referenced by V.V2 as an
  evidence-pack element; V.V3 does not validate training but does
  cite the training-completion rate in the §164.404(c)(1)(D) "what
  the covered entity is doing" narrative slot.
- **CIRCIA 72-hour reporting** — a HIPAA breach that is also a
  CIRCIA-covered cyber-incident triggers BOTH clocks. The CIRCIA
  workflow is at `docs/CIRCIA-WORKFLOW.md` and the parent G.G2
  incident record carries the CIRCIA classification. V.V3 cross-
  links to the CIRCIA submission ID but does not compute the
  CIRCIA clock.
- **SEC Form 8-K Item 1.05 disclosure** — handled by the G.G2
  SEC-8K extension when the registrant is subject to SEC reporting.
- **EU GDPR Article 33 / UK GDPR 72-hour breach notification** —
  handled by LOOP-U privacy frameworks.

## 4. Inputs

### 4.1 Incident input from LOOP-G.G2

```ts
interface IncidentInput {
  incident_id: string;                          // FK to LOOP-G.G2 incident_records.id
  incident_kind: 'ransomware' | 'data-exfil' | 'misconfiguration' |
                 'lost-device' | 'insider-misuse' | 'phishing' |
                 'subprocessor-incident' | 'other';
  system_detection_at: string;                  // ISO 8601 UTC — SIEM/SOC first alert
  analyst_triage_at: string | null;             // First human triage
  officer_briefed_at: string | null;            // CISO/Privacy Officer briefed
  discovery_acknowledged_at: string;            // Formal "breach discovered" declaration
  affected_data_classifications: string[];      // From LOOP-V.V4 ePHI tagger output
  affected_individuals_count_estimate: number;  // Upper bound at triage; refined later
  affected_individuals_count_final: number | null;
  affected_jurisdictions: Array<{               // Per-state breakdown for §164.406 evaluation
    iso_3166_2_code: string;                    // e.g. 'US-NY', 'US-CA'
    resident_count: number;
  }>;
  csp_role: 'covered-entity' | 'business-associate';
  affected_ce_ids: string[];                    // FK to V.V1 baa_registry when csp_role='business-associate'
  encryption_status: 'encrypted-per-hhs-guidance' | 'encrypted-other' |
                     'plaintext' | 'unknown';
  encryption_evidence_url: string | null;       // Required when status='encrypted-per-hhs-guidance'
  le_delay_kind: 'written' | 'oral' | 'none';
  le_delay_official_identity: string | null;
  le_delay_received_at: string | null;
  le_delay_expires_at: string | null;
  parent_circia_submission_id: string | null;   // Cross-reference if CIRCIA also fires
}
```

### 4.2 4-factor risk-assessment operator input

```ts
interface FourFactorRiskAssessmentInput {
  breach_id: string;
  assessor_user_id: string;                     // From tracker DB users
  assessor_role: 'privacy-officer' | 'ciso' | 'designated-assessor';
  factor_1_nature_extent: {
    score: 'low' | 'med' | 'high';
    narrative: string;                          // min 150 chars
    identifiers_involved: string[];             // subset of the 18 HIPAA identifiers
    reidentification_likelihood: 'low' | 'med' | 'high';
    evidence_url: string | null;
  };
  factor_2_unauthorized_recipient: {
    score: 'low' | 'med' | 'high';
    narrative: string;                          // min 150 chars
    recipient_kind: 'internal-workforce' | 'authorized-other-entity' |
                    'unauthorized-individual' | 'unknown';
    recipient_identity_known: boolean;
    evidence_url: string | null;
  };
  factor_3_actual_acquisition_viewed: {
    score: 'low' | 'med' | 'high';
    narrative: string;                          // min 150 chars
    forensic_evidence_kind: 'log-confirmed-no-access' |
                            'log-confirmed-access' | 'no-logs-available' |
                            'forensic-attestation';
    evidence_url: string | null;
  };
  factor_4_risk_mitigated: {
    score: 'low' | 'med' | 'high';
    narrative: string;                          // min 150 chars
    mitigation_steps: string[];                 // free-text bullets
    recipient_attestation_received: boolean;    // e.g. "I deleted the email"
    evidence_url: string | null;
  };
  overall_finding: 'breach' | 'low-probability-of-compromise';
  signature_required: boolean;                  // true when overall_finding='low-probability-of-compromise'
  webauthn_assertion: string | null;            // base64 WebAuthn signature payload
  piv_signature: string | null;                 // PIV/CAC alternative
}
```

### 4.3 Operator config gate

```yaml
compliance:
  hipaa:
    role: business-associate              # covered-entity | business-associate | none
    breach_notification:
      enabled: true
      ba_to_ce_internal_target_days: 30   # default 30; per-BAA can shorten to 5/10/15
      unreasonable_delay_threshold_days: 30
      hhs_portal_url: https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf
      letter_template_path: cloud-evidence/templates/hipaa-breach-letter.docx
      media_template_path: cloud-evidence/templates/hipaa-media-notice.docx
      ba_to_ce_template_path: cloud-evidence/templates/hipaa-ba-to-ce.docx
      annual_submission_due_day: '03-01'  # March 1 every year
      reminder_offsets_days: [90, 30, 7]
      historical_baseline_source: https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/reports-congress/index.html
```

## 5. Outputs

### 5.1 Individual notice letter envelope

Path: `out/hipaa-breach/<breach_id>/individual-notice-<batch>.docx`
+ sidecar `out/hipaa-breach/<breach_id>/individual-notice-<batch>.envelope.json`.

```ts
interface IndividualNoticeEnvelope {
  schema_version: '1.0.0';
  envelope_kind: 'hipaa-individual-notice';
  breach_id: string;
  batch_id: string;
  affected_individuals_in_batch: number;
  generated_at: string;                         // ISO 8601 UTC
  letter_sections: {                            // each maps to §164.404(c)(1)
    a_brief_description: string;
    b_phi_types_involved: string[];
    c_steps_individuals_should_take: string[];
    d_what_csp_is_doing: string;
    e_contact_procedures: {
      toll_free_phone: string;
      email_address: string;
      website_url: string;
      postal_address: string;
    };
  };
  clock: {
    discovered_at: string;
    notify_by: string;                          // discovered_at + 60 calendar days
    notified_at: string | null;
    unreasonable_delay_rationale: string | null;
  };
  provenance: {
    incident_id: string;
    four_factor_version_id: string;
    v_v1_catalog_sha256: string;
    v_v3_source_mirrors_sha256: Record<string, string>;
  };
  docx_sha256: string;
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}
```

### 5.2 HHS Secretary submission envelope

Path: `out/hipaa-breach/<breach_id>/hhs-secretary-submission.envelope.json`.

```ts
interface HHSSecretarySubmissionEnvelope {
  schema_version: '1.0.0';
  envelope_kind: 'hipaa-hhs-secretary';
  breach_id: string;
  submission_path: '500+ contemporaneous' | '<500 annual';
  hhs_portal_url: 'https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf';
  wizard_fields: {                              // matches HHS portal wizard 1:1
    name_of_covered_entity: string;
    name_of_business_associate: string | null;
    type_of_breach: 'theft' | 'loss' | 'improper-disposal' |
                    'unauthorized-access' | 'hacking-it-incident' | 'other';
    location_of_breached_info: 'desktop' | 'laptop' | 'network-server' |
                               'email' | 'ehr' | 'paper-films' |
                               'other-portable-device' | 'other';
    type_of_phi_involved: string[];
    safeguards_in_place_prior: string[];
    actions_taken_in_response: string[];
    individuals_affected_count: number;
    breach_start_date: string;
    breach_discovered_date: string;
    individuals_notified_date: string | null;
    media_notified_date: string | null;
  };
  manual_submission_checklist: Array<{
    step_number: number;
    description: string;
    operator_completed_at: string | null;
    operator_user_id: string | null;
  }>;
  hhs_confirmation_number: string | null;       // operator pastes after manual submit
  hhs_submitted_at: string | null;
  provenance: { /* same shape as 5.1.provenance */ };
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}
```

### 5.3 Media notice envelope

Path: `out/hipaa-breach/<breach_id>/media-notice-<state>.docx` +
sidecar `out/hipaa-breach/<breach_id>/media-notice-<state>.envelope.json`.

```ts
interface MediaNoticeEnvelope {
  schema_version: '1.0.0';
  envelope_kind: 'hipaa-media-notice';
  breach_id: string;
  state_iso_3166_2: string;                     // e.g. 'US-NY'
  affected_residents_in_state: number;          // > 500 (precondition)
  prominent_media_outlets: Array<{              // operator-supplied per state
    outlet_name: string;
    contact_email: string;
    contact_phone: string;
  }>;
  press_release_sections: {                     // same five §164.404(c)(1) elements
    a_brief_description: string;
    b_phi_types_involved: string[];
    c_steps_individuals_should_take: string[];
    d_what_csp_is_doing: string;
    e_contact_procedures: { /* same */ };
  };
  clock: { /* same shape as 5.1.clock */ };
  provenance: { /* same */ };
  docx_sha256: string;
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}
```

### 5.4 BA-to-CE notification envelope

Path: `out/hipaa-breach/<breach_id>/ba-to-ce-<ce_id>.docx` +
sidecar `out/hipaa-breach/<breach_id>/ba-to-ce-<ce_id>.envelope.json`.

```ts
interface BAtoCENotificationEnvelope {
  schema_version: '1.0.0';
  envelope_kind: 'hipaa-ba-to-ce-notification';
  breach_id: string;
  ce_id: string;                                // FK to V.V1 baa_registry
  csp_role: 'business-associate';
  notification_sections: {                      // §164.410(c)
    identified_individuals: Array<{
      individual_id_hash: string;               // sha256 of unique identifier
      identifier_types_involved: string[];      // subset of 18 HIPAA identifiers
    }>;
    other_404c_information: {
      brief_description: string;
      phi_types_involved: string[];
      steps_individuals_should_take: string[];
      what_csp_is_doing: string;
      contact_procedures: { /* same */ };
    };
  };
  clock: {
    discovered_at: string;
    ce_notify_by: string;                       // discovered_at + 60 calendar days (statutory cap)
    ce_notify_internal_target: string;          // discovered_at + N days (per BAA)
    notified_at: string | null;
    days_elapsed_at_notification: number | null;
  };
  baa_reference: {
    ce_legal_name: string;
    baa_signed_date: string;
    baa_notification_clause_text_verbatim: string;
  };
  provenance: { /* same */ };
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}
```

### 5.5 Tracker DB schema (migration 0053)

Path: `cloud-evidence/tracker/db/migrations/0053_hipaa_breach_log.sql`.

```sql
CREATE TABLE breach_log (
  breach_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incident_records(id),
  csp_role TEXT NOT NULL CHECK (csp_role IN ('covered-entity','business-associate')),
  discovered_at TIMESTAMPTZ NOT NULL,
  system_detection_at TIMESTAMPTZ NOT NULL,
  analyst_triage_at TIMESTAMPTZ,
  officer_briefed_at TIMESTAMPTZ,
  affected_individuals_count_estimate INT NOT NULL,
  affected_individuals_count_final INT,
  encryption_status TEXT NOT NULL CHECK (encryption_status IN (
    'encrypted-per-hhs-guidance','encrypted-other','plaintext','unknown')),
  encryption_evidence_url TEXT,
  le_delay_kind TEXT NOT NULL DEFAULT 'none',
  le_delay_official_identity TEXT,
  le_delay_received_at TIMESTAMPTZ,
  le_delay_expires_at TIMESTAMPTZ,
  current_finding TEXT NOT NULL DEFAULT 'pending-4-factor'
    CHECK (current_finding IN ('pending-4-factor','breach','low-probability-of-compromise',
                                'excluded-164-402-1')),
  current_version_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT NOT NULL
);

CREATE TABLE breach_log_versions (
  version_id TEXT PRIMARY KEY,
  breach_id TEXT NOT NULL REFERENCES breach_log(breach_id),
  version_seq INT NOT NULL,
  prior_version_hash TEXT,                       -- NULL for v1; sha256 for v2+
  this_version_hash TEXT NOT NULL,               -- sha256 of canonicalized version body
  version_body_json JSONB NOT NULL,              -- complete snapshot at this version
  change_reason TEXT NOT NULL,
  signed_by_user_id TEXT NOT NULL,
  webauthn_assertion TEXT,
  piv_signature TEXT,
  ed25519_signature TEXT NOT NULL,
  rfc3161_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (breach_id, version_seq)
);

CREATE TABLE breach_affected_jurisdictions (
  breach_id TEXT NOT NULL REFERENCES breach_log(breach_id),
  iso_3166_2_code TEXT NOT NULL,
  resident_count INT NOT NULL,
  media_notice_required BOOLEAN NOT NULL,        -- computed: resident_count > 500
  PRIMARY KEY (breach_id, iso_3166_2_code)
);

CREATE TABLE breach_affected_ces (
  breach_id TEXT NOT NULL REFERENCES breach_log(breach_id),
  ce_id TEXT NOT NULL REFERENCES baa_registry(ce_id),
  notified_at TIMESTAMPTZ,
  days_elapsed_at_notification INT,
  PRIMARY KEY (breach_id, ce_id)
);

CREATE TABLE breach_notifications_emitted (
  notification_id TEXT PRIMARY KEY,
  breach_id TEXT NOT NULL REFERENCES breach_log(breach_id),
  notification_kind TEXT NOT NULL CHECK (notification_kind IN (
    'individual','hhs-secretary','media','ba-to-ce')),
  jurisdiction_or_ce_id TEXT,                    -- state code for media, ce_id for ba-to-ce
  envelope_path TEXT NOT NULL,
  envelope_sha256 TEXT NOT NULL,
  emitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  submitted_at TIMESTAMPTZ,                      -- operator records manual submit
  hhs_confirmation_number TEXT
);

CREATE INDEX idx_breach_log_discovered_at ON breach_log(discovered_at);
CREATE INDEX idx_breach_log_current_finding ON breach_log(current_finding);
CREATE INDEX idx_breach_log_versions_breach ON breach_log_versions(breach_id, version_seq);
```

### 5.6 Tracker UI status pane

Path: `cloud-evidence/tracker/ui/hipaa-breach-status-pane.tsx`.

Renders, per active breach record:

- Four clocks side-by-side (individual / HHS / media-per-state /
  BA-to-CE) with countdown, color-coded by urgency.
- 4-factor matrix view (4×3 cells with current scores + narrative
  excerpt + last-edited-by).
- Version history with hash-chain visualization (each version
  shows `prior_version_hash` → `this_version_hash` link).
- Per-jurisdiction breakdown with `media_notice_required` flag.
- Affected-CE list with per-CE notification status.
- LE-delay banner when active (countdown + official identity).
- Emit-artifact buttons that POST to
  `/api/hipaa-breach/<breach_id>/emit/<kind>` returning the
  signed envelope.

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--hipaa-breach-notification` (or env
   `CLOUD_EVIDENCE_HIPAA_BREACH_NOTIFICATION`). If neither set,
   exit 0 with `LOOP-V.V3 skipped — flag not set`.
2. **Check operator config gate.** Read
   `config.yaml::compliance.hipaa.role` and
   `compliance.hipaa.breach_notification.enabled`. If role=`none`
   or enabled=`false`, exit 0 with skip log.
3. **Verify dependency artifacts.** Read V.V1 HIPAA Security Rule
   catalog and verify its Ed25519 signature. Failure → exit 2
   with `HIPAASecurityRuleCatalogSignatureInvalidError`. Read
   V.V1 BAA registry. If `csp_role='business-associate'` and
   registry is empty, exit 2 with `BAARegistryEmptyForBAModeError`.
4. **Sign-test the signing key.** Call
   `core/sign.ts::testSign(key_ref)`. Failure → exit 2.
5. **Verify tracker DB migration.** Confirm migration 0053 has
   been applied (check `schema_migrations` table). Failure → exit 2
   with `BreachLogMigrationMissingError`.

### Phase B — Triage incoming incident

6. **Read incident input** from the tracker DB (joined to
   `incident_records` via `incident_id`). Validate required fields
   per the §4.1 schema.
7. **Apply §164.402(1) categorical exclusion checks.** Pseudocode:
   ```
   if incident.kind == 'workforce-unintentional-good-faith':
     finding = 'excluded-164-402-1-i'
   elif incident.kind == 'inadvertent-disclosure-between-authorized':
     finding = 'excluded-164-402-1-ii'
   elif incident.kind == 'unauthorized-recipient-cannot-retain':
     finding = 'excluded-164-402-1-iii'
   ```
   These are operator-classified at triage; V.V3 surfaces the
   exclusion paths in the UI as explicit radio choices with the
   verbatim §164.402(1) text. Selection requires
   `excluded_rationale: text` (min 150 chars).
8. **Apply §164.402(1) encryption Safe Harbor check.** If
   `incident.encryption_status == 'encrypted-per-hhs-guidance'` AND
   `incident.encryption_evidence_url` is populated AND the linked
   evidence (operator-supplied attachment) cites NIST SP 800-111
   (at-rest) or NIST SP 800-52 Rev 2 (in-transit) or FIPS 140-2/3
   validated module, set `finding = 'safe-harbor-encryption'` and
   exit the breach lifecycle (no notification required). Failed
   evidence link → `safe-harbor-claim-pending-evidence` diagnostic.

### Phase C — 4-factor risk assessment

9. **Open 4-factor input form** in tracker UI. Operator (must have
   `assessor_role IN ('privacy-officer','ciso','designated-assessor')`)
   completes all four factors per §4.2 schema.
10. **Validate narrative minimums.** Each factor narrative >= 150
    chars; renderer rejects shorter inputs with
    `FourFactorNarrativeTooShortError(factor)`.
11. **Evaluate overall finding.** Pseudocode:
    ```
    all_low = factor_1.score == 'low'
              and factor_2.score == 'low'
              and factor_3.score == 'low'
              and factor_4.score == 'low'
    if all_low and operator.overall_finding == 'low-probability-of-compromise':
      require_digital_signature(operator)         # WebAuthn or PIV
      finding = 'low-probability-of-compromise'
    else:
      finding = 'breach'
    ```
12. **Append to `breach_log_versions`.** Compute new version body
    (canonicalize per RFC 8785), compute `this_version_hash =
    sha256(version_body_canon_bytes)`, read `prior_version_hash`
    from current head version (or NULL for v1), insert new row
    with monotonically incremented `version_seq`. Sign body with
    Ed25519. Timestamp with RFC 3161. Update
    `breach_log.current_version_id` to point at the new version.
13. **If finding == 'low-probability-of-compromise':** the breach
    lifecycle ends here. The signed 4-factor envelope is the
    audit-defense artifact. Render as
    `out/hipaa-breach/<breach_id>/four-factor-finding.envelope.json`.
    Tracker UI surfaces the finding as an "OCR audit-ready"
    badge. Exit 0.

### Phase D — Clock arithmetic (when finding == 'breach')

14. **Compute individual notification deadline** per §164.404(b):
    ```
    individual_notify_by = breach_log.discovered_at + 60 calendar days
    ```
    Calendar-day arithmetic: each day boundary is midnight UTC.
    Leap year handling: Feb 29 counts as one day. NO business-day
    exclusion (this distinguishes the HIPAA clock from FAR §889
    and CIRCIA).

15. **Compute HHS Secretary notification deadline** per §164.408:
    ```
    if affected_individuals_count_final >= 500:
      hhs_notify_by = individual_notify_by         # contemporaneous
      hhs_submission_path = '500+ contemporaneous'
    else:
      hhs_notify_by = end_of_CY(discovered_at) + 60 calendar days
      hhs_submission_path = '<500 annual'
    ```
    Helper: `end_of_CY(dt)` returns `Date(dt.year, 12, 31, 23, 59, 59, UTC)`.

16. **Compute per-state media notice deadlines** per §164.406:
    ```
    for jurisdiction in breach_affected_jurisdictions:
      if jurisdiction.resident_count > 500:
        jurisdiction.media_notify_by = individual_notify_by
        jurisdiction.media_notice_required = true
      else:
        jurisdiction.media_notice_required = false
    ```
    The §164.406(a) threshold is `> 500` (strictly greater than),
    not `>= 500` — read verbatim. T-V3-08 pins the boundary at 500
    (no media notice required) vs 501 (required).

17. **Compute BA-to-CE deadline** per §164.410 (when
    `csp_role='business-associate'`):
    ```
    ba_to_ce_statutory_by = discovered_at + 60 calendar days
    ba_to_ce_internal_target = discovered_at
       + config.compliance.hipaa.breach_notification.ba_to_ce_internal_target_days
    ```

18. **Apply LE-delay pause** per §164.412 if active. Pseudocode:
    ```
    if breach_log.le_delay_kind != 'none':
      if le_delay_kind == 'written':
        all_deadlines += (le_delay_expires_at - le_delay_received_at)
      elif le_delay_kind == 'oral':
        pause_until = min(le_delay_received_at + 30 days, le_delay_expires_at or +inf)
        all_deadlines += (pause_until - le_delay_received_at)
    ```

19. **Surface unreasonable-delay warning** when current time -
    `discovered_at` > 30 days AND no notification yet emitted. UI
    requires operator to populate
    `unreasonable_delay_rationale: text` (min 200 chars) before
    accepting the late notification.

### Phase E — Artifact rendering

20. **Render individual-notice letter** (`.docx` via
    `hipaa-breach-letter-docx.ts`). Hard-fail on missing
    §164.404(c)(1) elements. OOXML zip-store (no compression on
    the inner XML so the SHA-256 is reproducible). Embed the
    verbatim §164.404(c)(1) text as a footer-comment block for
    auditor reference. Batch by 5,000 letters per file for
    operational manageability.
21. **Render HHS Secretary submission packet** as structured JSON
    matching the HHS Breach Portal wizard fields 1:1
    (`hipaa-hhs-secretary-submitter.ts`). Render a
    manual-submission checklist `.md` alongside enumerating each
    portal step.
22. **Render per-state media notices** (`hipaa-media-notice.ts`).
    One `.docx` per state where `media_notice_required = true`.
    Press-release format with §164.404(c) content elements.
23. **Render BA-to-CE notifications** (`hipaa-ba-to-ce-notification.ts`).
    One `.docx` per affected CE. Includes §164.410(c) identified-
    individuals list + §164.404(c) content elements.
24. **Sign every artifact.** Ed25519 detached signature on every
    `.docx` + every `.envelope.json`. RFC 3161 timestamp every
    signature.
25. **Insert `breach_notifications_emitted` rows** for every
    emitted artifact with `envelope_sha256`.

### Phase F — Annual aggregator (cron)

26. **Annual cron** (configured via
    `scheduled-tasks::hipaa-annual-breach-submission`) runs on
    March 1 each year (or operator-configured day). For every
    `<500` breach with `discovered_at` in the prior CY and
    `hhs_submitted_at IS NULL`, aggregate into a single
    `out/hipaa-breach/annual/hhs-annual-CYYYYY.envelope.json` +
    `.docx` packet. Tracker UI surfaces banner at T-90 / T-30 /
    T-7 days before March 1.

### Phase G — Persist + announce

27. **Append CHANGELOG entry** per emitted artifact bundle (the
    slice-completion procedure handles the slice's CHANGELOG entry;
    per-incident emissions log to the tracker's audit table).
28. **Emit run log** to `out/hipaa-breach-run-<breach_id>-<ts>.log`
    capturing: triage outcome, 4-factor finding, clocks computed,
    artifacts emitted with SHA-256s.

## 7. Files to create / modify

Absolute paths under `/Users/kenith.philip/FedRAMP 20x/`:

- `cloud-evidence/core/hipaa-breach-classifier.ts` — §164.402(1)
  categorical-exclusion + Safe Harbor evaluator; returns one of
  `breach-candidate | excluded-164-402-1-i | excluded-164-402-1-ii
  | excluded-164-402-1-iii | safe-harbor-encryption`.
- `cloud-evidence/core/hipaa-breach-4factor.ts` — 4-factor
  risk-assessment validator + finding computation; enforces
  narrative-min-chars + signature requirements.
- `cloud-evidence/core/hipaa-60day-clock.ts` — calendar-day clock
  arithmetic engine for individual / HHS / media / BA-to-CE
  deadlines; LE-delay pause; unreasonable-delay detector.
- `cloud-evidence/core/hipaa-breach-notification.ts` — top-level
  orchestrator (Phase A-G above); wires the classifier + 4-factor
  + clock + emitters together.
- `cloud-evidence/core/hipaa-breach-letter-docx.ts` — individual
  notice `.docx` renderer (OOXML zip-store, reproducible SHA-256).
- `cloud-evidence/core/hipaa-hhs-secretary-submitter.ts` — HHS
  portal wizard-matching JSON packet + manual-submission checklist.
- `cloud-evidence/core/hipaa-media-notice.ts` — per-state media
  notice `.docx` renderer.
- `cloud-evidence/core/hipaa-ba-to-ce-notification.ts` — BA-to-CE
  notification `.docx` + identified-individuals list renderer.
- `cloud-evidence/tracker/db/migrations/0053_hipaa_breach_log.sql`
  — append-only schema (see §5.5).
- `cloud-evidence/tracker/server/routes/hipaa-breach.ts` — REST
  endpoints for breach lifecycle (POST classify, POST 4-factor,
  GET clocks, POST emit-artifact).
- `cloud-evidence/tracker/ui/hipaa-breach-status-pane.tsx` — UI
  pane (see §5.6).
- `cloud-evidence/test/hipaa-breach-classifier.test.ts` — 18+
  test cases (see §8).
- `cloud-evidence/test/fixtures/hipaa-breach-sample-incidents.json`
  — incident-input fixture corpus.
- `cloud-evidence/test/fixtures/hipaa-4factor-sample-narratives.json`
  — 4-factor input fixture corpus.
- `cloud-evidence/test/fixtures/hipaa-baa-registry-sample.json` —
  BAA registry fixture for BA-mode tests.
- `cloud-evidence/templates/hipaa-breach-letter.docx` — operator-
  customizable .docx template for individual notice.
- `cloud-evidence/templates/hipaa-media-notice.docx` — operator-
  customizable .docx template for media press release.
- `cloud-evidence/templates/hipaa-ba-to-ce.docx` — operator-
  customizable .docx template for BA-to-CE notification.
- `cloud-evidence/docs/sources/hipaa-breach/` — mirrored HHS
  source pages (one-time operator action; SHA-256 pinned).
- `cloud-evidence/docs/STATUS.md` — V.V3 row updated to `done` at
  slice close.
- `cloud-evidence/docs/loops/LOOP-V-SPEC.md` — V.V3 row in status
  table updated.
- `CHANGELOG.md` — Unreleased entry appended.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T-V3-01 | Clearly material breach — 5,000 individuals affected by ransomware exfil, plaintext PHI, two states each <500 → individual notice fires, HHS contemporaneous fires, no media notice | `fixtures/hipaa-breach-sample-incidents.json#material-5000` | finding=`breach`; individual envelope emitted; HHS envelope `submission_path='500+ contemporaneous'`; no media envelopes | All three artifact paths exist + signatures verify |
| T-V3-02 | <500 path — 250 individuals affected, plaintext PHI, all in NY → individual notice fires, HHS goes to annual aggregator, no media notice | `fixtures/hipaa-breach-sample-incidents.json#sub-500-NY-only` | finding=`breach`; individual envelope emitted; HHS submission `path='<500 annual'`; aggregator picks up at March 1 | Per-row equality + annual cron test |
| T-V3-03 | Marginal 4-factor — all four factors `low` with non-empty narratives → finding=`low-probability-of-compromise`; WebAuthn signature required; no notifications fire | `fixtures/hipaa-4factor-sample-narratives.json#all-low-mitigated` | finding=`low-probability-of-compromise`; signature recorded; lifecycle ends | Boolean + signature presence |
| T-V3-04 | Marginal 4-factor — one factor `med` (others `low`); operator attempts `low-probability-of-compromise` → rejected | `fixtures/hipaa-4factor-sample-narratives.json#one-med` | classifier returns `breach`; notification path activates | Override rejection assertion |
| T-V3-05 | Marginal 4-factor — operator attempts narrative under 150 chars → `FourFactorNarrativeTooShortError` | `fixtures/hipaa-4factor-sample-narratives.json#short-narrative` | Exception thrown at factor 1 narrative | Exception type assertion |
| T-V3-06 | LE-delay (written) pauses the 60-day clock → individual notice deadline extended by delay duration | `fixtures/hipaa-breach-sample-incidents.json#le-delay-written-15days` | individual_notify_by = base + 60 + 15 calendar days | Computed date equality |
| T-V3-07 | LE-delay (oral, no follow-up written) pauses for max 30 days | `fixtures/hipaa-breach-sample-incidents.json#le-delay-oral` | pause = 30 calendar days (cap) | Computed date equality |
| T-V3-08 | Multi-state media-notice boundary — state A has 500 (no media), state B has 501 (media required), state C has 1000 (media required) | `fixtures/hipaa-breach-sample-incidents.json#multi-state-boundary` | A.media_notice_required=false; B.media_notice_required=true; C.media_notice_required=true | Per-state boolean check |
| T-V3-09 | BAA chain — BA discovers breach, fires BA-to-CE within 30-day internal target; CE then has full 60-day window | `fixtures/hipaa-breach-sample-incidents.json#ba-chain-30day-internal` | ba_to_ce envelope emitted at T+30; ce_notify_by = T_ba_discovered + 60 days | Date arithmetic + envelope presence |
| T-V3-10 | BAA chain — BA exhausts day 58 → CE only has 2 days; tracker UI flags `ba-late-anchor-warning` | `fixtures/hipaa-breach-sample-incidents.json#ba-chain-day58` | warning surfaced; envelope still emitted | Warning assertion + envelope presence |
| T-V3-11 | Calendar-day arithmetic — discovery on Dec 31 → individual_notify_by = March 1 (or Feb 29 in leap year) | (synthetic input with Dec 31 anchor) | notify_by ISO equals expected date | String equality |
| T-V3-12 | Calendar-day arithmetic — leap year Feb 29 boundary | (synthetic input with discovery Jan 1 leap year) | notify_by = March 1 (60 days incl Feb 29) | String equality |
| T-V3-13 | Encryption Safe Harbor §164.402(1)(i) — encrypted at rest with FIPS 140-3 evidence link → no breach notification | `fixtures/hipaa-breach-sample-incidents.json#safe-harbor-fips140-3` | finding=`safe-harbor-encryption`; lifecycle ends; no envelopes emitted | finding equality + envelope absence |
| T-V3-14 | Encryption Safe Harbor missing evidence URL → `safe-harbor-claim-pending-evidence` diagnostic; lifecycle proceeds to 4-factor | `fixtures/hipaa-breach-sample-incidents.json#safe-harbor-no-evidence` | diagnostic emitted; finding=`pending-4-factor` | Diagnostic assertion + finding equality |
| T-V3-15 | Limited Data Set exception — incident affects LDS-only data per V.V4 tagger → §164.402(2) factor 1 reidentification_likelihood='low' streamlined; finding can be `low-probability-of-compromise` | `fixtures/hipaa-breach-sample-incidents.json#lds-only` | factor 1 score='low'; finding=`low-probability-of-compromise` allowed | Per-factor equality |
| T-V3-16 | Transitive subcontractor breach — subprocessor (downstream BA of CSP) reports breach; CSP must propagate to all affected CEs | `fixtures/hipaa-breach-sample-incidents.json#subprocessor-breach` | One BA-to-CE envelope per affected CE; envelope `provenance.upstream_subprocessor` populated | Envelope count + provenance field |
| T-V3-17 | Append-only hash chain — submitting v2 of 4-factor with `change_reason` produces row with `prior_version_hash` = v1 `this_version_hash` | (synthetic 2-version sequence) | hash chain verifies; v2.prior_version_hash === v1.this_version_hash | Hash equality |
| T-V3-18 | Hash chain tamper detection — mutating v1 body bytes and re-computing v2 → `BreachLogHashChainInvalidError` | (mutated v1 row) | Verification function throws named error | Exception type assertion |
| T-V3-19 | Letter §164.404(c)(1) element enforcement — missing `c_steps_individuals_should_take` array → `HIPAALetterMissingRequiredElementError(c)` | (incomplete envelope) | renderer throws at element C | Exception type assertion |
| T-V3-20 | HHS portal wizard field mapping — every `wizard_fields[*]` key maps to a known HHS Breach Portal field per the captured 2026-06-08 mirror | `fixtures/hipaa-hhs-portal-wizard-mirror-2026-06-08.json` | All keys present in mirror; no extra keys | Set equality |
| T-V3-21 | Annual aggregator — three <500 breaches in CY2026 produce one annual envelope for March 1 2027 with three child-breach references | `fixtures/hipaa-breach-sample-incidents.json#annual-aggregator-3` | annual envelope has `child_breach_count=3`; SHA-256 verifies | Count + signature assertion |
| T-V3-22 | REO Rule 4 — auto-submission attempt to HHS portal URL is hard-blocked by `core/sign.ts` policy check | (synthetic call attempting POST to ocrportal) | Policy throws `AutomatedFederalSubmissionForbiddenError` | Exception type assertion |
| T-V3-23 | Provenance — every emitted envelope carries V.V1 catalog SHA-256 + V.V3 source-mirror SHA-256s | (any happy-path emit) | provenance block fields non-empty | Non-empty assertion |

## 9. Risks

| id | risk | likelihood | impact | mitigation |
|---|---|---|---|---|
| R-V3-01 | Operator misclassifies an incident as `excluded-164-402-1-i` (workforce-good-faith exclusion) when the workforce member's action actually exceeded scope, suppressing notification. HHS-OCR has cited this pattern in enforcement actions. | medium | high (failure-to-notify finding; willful-neglect tier) | UI exclusion path requires `excluded_rationale: text` (min 150 chars); the rationale + operator identity become part of the append-only hash chain; quarterly internal audit report surfaces all exclusions with rationales for legal review |
| R-V3-02 | 4-factor `low-probability-of-compromise` over-classification. Empirical pattern: BAs use it to dodge notification overhead; HHS Resolution Agreements (e.g. CHSPSC 2020, $2.3M) penalize this. | high | high | Tracker UI surfaces historical statistics ("Your last 10 assessments: N low-prob, M breach"); >70% low-prob rate triggers `over-classification-warning`; WebAuthn/PIV signature on every low-prob finding; cross-reference to HHS OCR Resolution Agreements registry calibrates expectations |
| R-V3-03 | Encryption Safe Harbor mis-claimed without meeting NIST SP 800-111 / 800-52 / FIPS 140-2/3 requirements. Plaintext-at-rest with TLS-only is a common false claim. | medium | high (loss of safe harbor → unnotified breach → enforcement action) | Safe Harbor claim requires `encryption_evidence_url` linking to operator-supplied evidence (KMS attestation, FIPS module certificate); V.V3 flags `safe-harbor-claim-pending-evidence` when evidence missing; cross-loop with LOOP-R cryptography evidence |
| R-V3-04 | BA-to-CE notification delay (BA exhausts day 58) leaves CE with insufficient time. HHS has cited "unreasonable delay" within the 60-day cap. | high | high (BA-side enforcement risk + CE-side cascade) | Internal target default 30 days; per-BAA configurable to 5/10/15 days; tracker UI countdown clock tracks against the tighter target; cross-loop integration test pins the day-58 case |
| R-V3-05 | Calendar-day vs business-day confusion. HIPAA is calendar-day; FAR §889 is 1-business-day; CIRCIA is 72-hour. Implementer mistakenly subtracts weekends. | medium | high (clock-miss enforcement risk) | `hipaa-60day-clock.ts` is a calendar-day-only engine with type-system enforcement (no `BusinessDayOffset` types); test corpus pins Dec 31 + leap-year boundary + weekend-discovery cases; cross-loop runbook cites the three different clock kinds |
| R-V3-06 | Multi-state media notice miss — operator counts aggregate (e.g. 600 across two states) and concludes no media notice, when §164.406(a) requires per-state evaluation. | medium | medium (state-by-state non-notification risk) | `breach_affected_jurisdictions` table forces per-state breakdown; UI per-state pane shows `media_notice_required` flag computed at row level; T-V3-08 pins multi-state boundary cases |
| R-V3-07 | Append-only hash chain corruption (e.g. DB index rebuild dropping rows). HHS audit defense depends on intact chain. | low | critical | DB schema has `UNIQUE (breach_id, version_seq)` constraint; `prior_version_hash` is verified on every read via `verifyBreachLogChain(breach_id)`; nightly cron verifies all chains and alerts on mismatch; PostgreSQL WAL retention extended to 90 days for chain reconstruction |
| R-V3-08 | HHS Breach Portal wizard field-shape drift — HHS updates the portal, V.V3's wizard_fields mapping goes stale, operator's hand-keyed values don't match new fields. | medium | medium (operational friction, not regulatory) | `hipaa-hhs-portal-wizard-mirror-YYYY-MM-DD.json` is refreshed quarterly via operator action; T-V3-20 fails when mirror drifts; CHANGELOG entry per refresh; tracker UI banner when mirror >90 days old |
| R-V3-09 | 60-day clock anchored at `discovery_acknowledged_at` rather than `system_detection_at` (or "would have known by reasonable diligence") creates a deliberately-late-anchor risk. HHS has cited this pattern. | high | high | Schema captures all four anchor timestamps; clock engine starts at the EARLIEST of system_detection, analyst_triage, or "would have known" (operator must justify in `discovery_anchor_rationale: text` if not earliest); audit report surfaces all anchors with >7-day spread |

## 10. Open questions

- **Q-V3-01.** Should the §164.412 LE-delay clock pause apply
  RETROACTIVELY when a written LE statement arrives mid-clock?
  Statutory text says delay starts when statement received; if a
  written statement arrives at day 20 specifying a 15-day delay,
  does the clock pause at day 20 or at day 0? **Tentative
  decision: pause at day 20** (statement-receipt anchor); the
  20 days already elapsed count against the operator. Confirm with
  HHS guidance and operator legal counsel.
- **Q-V3-02.** When a single incident triggers BOTH HIPAA breach
  notification AND CIRCIA 72-hour reporting AND SEC Form 8-K Item
  1.05 disclosure, what's the cross-artifact provenance model? V.V3
  cross-links to CIRCIA submission ID and G.G2-SEC-8K envelope;
  should it ALSO embed their SHA-256s into its own provenance? Or
  is forward-only linking sufficient? **Tentative decision: forward
  linking only** (V.V3 → CIRCIA submission ID; CIRCIA workflow
  back-links). Reduces re-emit cascades. REQUIRES-RESEARCH on
  3PAO expectation.
- **Q-V3-03.** Should V.V3 emit a `low-probability-of-compromise`
  finding's signed envelope to HHS proactively as a "we
  considered this and concluded no breach" record, or only retain
  it locally for audit? HHS guidance does not require submission of
  non-breach findings, but some operators submit defensively.
  **Tentative decision: retain locally only**; surface in OCR
  audit-package on demand.
- **Q-V3-04.** When the NPRM is finalized (expected 2026-late or
  2027), it may shorten the BA-to-CE clock or impose new
  encryption Safe Harbor preconditions. V.V3's clock engine and
  Safe Harbor evaluator are version-pinned to current rule.
  Coordination with V.V5 (NPRM-readiness pack) needed.
  **REQUIRES-RESEARCH on NPRM finalization horizon.**
- **Q-V3-05.** Should the §164.404(c)(1)(C) "steps individuals
  should take" content be operator-authored per incident, or
  curated from a standard set (e.g. credit monitoring offer,
  identity theft awareness)? Different breach kinds warrant
  different guidance. **Tentative decision: incident-kind-keyed
  defaults (operator-overridable)** with templates per incident
  kind in `templates/hipaa-breach-steps-by-kind.yaml`.

## 11. REQUIRES-OPERATOR-INPUT

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `compliance.hipaa.role` | enum | `['covered-entity','business-associate','none']` | `config.yaml` + tracker Settings → HIPAA tab | V.V3 exits 2 if value missing AND `--hipaa-breach-notification` flag set; otherwise exits 0 (no-op) |
| `compliance.hipaa.breach_notification.ba_to_ce_internal_target_days` | int | 1..60 | `config.yaml` (default 30) | falls back to 30 with warning logged |
| `compliance.hipaa.breach_notification.letter_template_path` | path | file exists + valid OOXML | `config.yaml` | uses bundled default template with warning |
| `compliance.hipaa.breach_notification.signing_key_ref` | string | KMS resource ARN/URI parseable by `core/sign.ts` | `config.yaml` | V.V3 exits 2 at startup sign-test |
| `incident.discovery_acknowledged_at` | timestamptz | ISO 8601 UTC; not in future | tracker UI Breach Triage form | required at row insert; DB NOT NULL |
| `incident.encryption_evidence_url` | URL | must be HTTPS or `s3://` / `gs://`; resolves to operator-attested evidence | tracker UI Breach Triage form | Safe Harbor claim fails without; diagnostic `safe-harbor-claim-pending-evidence` |
| `4_factor.factor_N.narrative` | text | min 150 chars each | tracker UI 4-factor form | renderer throws `FourFactorNarrativeTooShortError` |
| `4_factor.webauthn_assertion` OR `4_factor.piv_signature` | base64 | valid WebAuthn or PIV signature | tracker UI 4-factor form (final step) | finding=`low-probability-of-compromise` rejected without signature |
| `letter_sections.e_contact_procedures.toll_free_phone` | E.164 phone number | non-empty + format-valid | tracker UI Letter Builder | `HIPAALetterMissingRequiredElementError(e)` |
| `hhs_confirmation_number` | string | HHS-format confirmation number | tracker UI HHS Submission tab | breach record remains in `submitted_at IS NULL` state until populated |
| `prominent_media_outlets[]` | array | non-empty when `media_notice_required=true` | tracker UI Media Notice tab | media envelope refuses to render without at least one outlet per state |
| `discovery_anchor_rationale` | text | min 100 chars when `discovered_at != system_detection_at` | tracker UI Breach Triage form | warning surfaced; eventually blocks notification emit if not populated |
| `unreasonable_delay_rationale` | text | min 200 chars when `notified_at - discovered_at > 30 days` | tracker UI Breach Status pane | individual-notice emit blocked until populated |
| `breach_notification.historical_baseline_source` | URL | accessible HHS report URL | `config.yaml` | falls back to bundled CY2024 snapshot with stale-warning |

## 12. Implementation log

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-08 | spec proposed | wf-vv3-spec | Specification authored via FedPy workflow; verbatim §164.400-414 source quotes pulled from eCFR (accessed 2026-06-08) and from the HHS OCR breach-notification landing page. House style matched against V.V1 sibling; risks register cross-referenced to LOOP-V-RISKS.md V-X7..V-X15, V-X32..V-X35. Tracker DB migration 0053 schema drafted with append-only hash chain. 23 test cases enumerated covering material/marginal/Safe-Harbor/LDS/subprocessor paths. | TBD | — |

## 13. Completion checklist

The following 7-step procedure is quoted verbatim from
`docs/SLICE-COMPLETION-PROCEDURE.md`. The implementer MUST execute
ALL 7 steps atomically with the slice-closing commit.

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
> Open `cloud-evidence/docs/loops/LOOP-V-SPEC.md`.
> Find the "Status tracking" section table.
> For the V.V3 row: status=done, commit=<hash>, date=<ISO>.
>
> ### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-V.V3: HIPAA Breach Notification Workflow (45 CFR §§164.400-414)
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>
>
> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-V-SPEC.md CHANGELOG.md
> git commit -m "LOOP-V.V3: HIPAA Breach Notification Workflow (45 CFR §§164.400-414)
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
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-V-SPEC.md
> git commit --amend --no-edit
> ```
>
> ### Step 7 — Push
> ```bash
> git push origin main
> ```

> Step 8: After commit lands, append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with 'git log --oneline -3'. Only THEN is the slice closed.
