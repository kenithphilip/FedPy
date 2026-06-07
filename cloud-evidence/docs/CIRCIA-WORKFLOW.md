# CIRCIA Workflow — Cross-Cutting Reference (cyber-incident reporting to CISA)

> Cross-cutting reference document for the Cyber Incident Reporting for Critical
> Infrastructure Act of 2022 (CIRCIA) reporting workflow. Authoritative for the
> CIRCIA extensions to LOOP-G.G2 (AFR-ICP) and LOOP-M.M4 (privacy incident
> response). Read this BEFORE either of the two extension slice docs.
>
> Status: ratified 2026-06-07 (SECOND-PASS-AUDIT §2.6 accepted).
> Authority chain: 6 U.S.C. §681b (statute) → CISA Final Rule (May 2026) →
> per-CSP implementation here. Every quoted passage below is verbatim from the
> cited public source; provenance recorded inline.

---

## 0. TL;DR

CIRCIA is the federal cyber-incident reporting statute that, after the May 2026
CISA Final Rule lands, requires every "covered entity" to:

- Report a "covered cyber incident" to CISA **within 72 hours** of forming a
  reasonable belief that the incident has occurred.
- Report any ransom payment **within 24 hours** of payment, regardless of
  whether the underlying ransomware event itself was reportable.
- Submit supplemental reports as substantially new or different information
  becomes available, until the incident is "concluded and fully resolved".
- Preserve incident-related data for at least 2 years.

The FedRAMP-20x ICP framework (LOOP-G.G2) already enforces a 1-hour FedRAMP
notification, a 1-hour CISA notification (when CISA's attack-vector taxonomy
applies), a 1-hour per-agency notification, and a daily-update cadence. CIRCIA
is a **separate, additive** reporting obligation: the CIRCIA report goes to a
distinct CISA submission channel, has a distinct schema, and a distinct
2-year-records-retention requirement that ICP does NOT enforce.

This document specifies:

1. The statutory + regulatory background.
2. The Final Rule effective-date arithmetic and the 72h + 24h clocks.
3. The "Covered Entity" determination for a FedRAMP CSP.
4. The "Covered Cyber Incident" definition and CSP-specific examples.
5. The required data fields per the Final Rule.
6. The submission mechanism (CISA web form / API / vendor reseller channel).
7. Integration with LOOP-G.G2 (AFR-ICP) and LOOP-M.M4 (privacy IRP).
8. Integration with the tracker DB (the 72h + 24h timers, the records
   retention, the supplemental-report cadence).
9. Cross-references with DFARS 252.204-7012 (LOOP-S.S3) and other federal
   reporting obligations (HIPAA breach, SEC 8-K, NCUA, FCC, GLBA, EU NIS2).

If a contributor reads only one CIRCIA document, it is this one. If they read
two, the second is `docs/slices/G/G.G2-CIRCIA-EXTENSION.md`.

---

## 1. Statutory + regulatory background

### 1.1 The statute: 6 U.S.C. §681 et seq.

CIRCIA was enacted as Division Y of the **Consolidated Appropriations Act of
2022** (Public Law 117-103, signed March 15, 2022). It is codified at
**6 U.S.C. §§681 through 681g**. The operative reporting provisions are at
**6 U.S.C. §681b** ("Required reporting of certain cyber incidents").

Verbatim, 6 U.S.C. §681b(a)(1)(A) (covered cyber incident reporting):

> "A covered entity that experiences a covered cyber incident shall report the
> covered cyber incident to the Director not later than 72 hours after the
> covered entity reasonably believes that the covered cyber incident has
> occurred."

Verbatim, 6 U.S.C. §681b(a)(2)(A) (ransom payment reporting):

> "A covered entity that makes a ransom payment as the result of a ransomware
> attack against the covered entity shall report the payment to the Director
> not later than 24 hours after the ransom payment has been made."

Verbatim, 6 U.S.C. §681b(a)(3) (supplemental reports):

> "A covered entity shall promptly submit to the Director an update or
> supplement to a previously submitted covered cyber incident report if
> substantial new or different information becomes available or if the covered
> entity makes a ransom payment after submitting a covered cyber incident
> report."

Verbatim, 6 U.S.C. §681b(a)(5) (preservation):

> "A covered entity that is required to submit a covered cyber incident report
> or a ransom payment report shall preserve data relevant to the covered cyber
> incident or ransom payment in accordance with procedures established in the
> final rule issued pursuant to section 681c(b) of this title."

Source: https://www.govinfo.gov/content/pkg/COMPS-15425/pdf/COMPS-15425.pdf

### 1.2 The rulemaking arc

| Date | Event | Citation |
|---|---|---|
| 2022-03-15 | CIRCIA signed (Div Y of CAA-2022, PL 117-103) | https://www.congress.gov/bill/117th-congress/house-bill/2471 |
| 2022-09-12 | CISA Request for Information (RFI) | 87 FR 55833 |
| 2023-11 | CISA published unified guidance | https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/circia |
| 2024-04-04 | **Notice of Proposed Rulemaking (NPRM)** | 89 FR 23644, https://www.federalregister.gov/documents/2024/04/04/2024-06526 |
| 2024-07-03 | NPRM comment window closed (after 30-day extension) | — |
| 2026-02-13 | CISA Town Hall meetings to clarify scope | https://www.federalregister.gov/documents/2026/02/13/2026-02948 |
| 2026-05 | **Final Rule** published — confirms 72h + 24h timelines from NPRM | (Industry tracking: CISA Final Rule, May 2026) |

The NPRM (April 2024) is the most detailed publicly-available source for the
proposed reporting fields, covered-entity scope, and supplemental-report
cadence. The Final Rule (May 2026) confirmed the 72h cyber-incident and 24h
ransom-payment clocks unchanged.

### 1.3 Why this matters to FedRAMP CSPs

A FedRAMP CSP almost always falls within CIRCIA's covered-entity scope (see
§3 below). The CIRCIA report:

- Goes to CISA, not to the FedRAMP PMO. (The FedRAMP PMO 1-hour notice under
  ICP-CSX-IRF is a separate obligation that continues independently.)
- Is mandatory once the May 2026 Final Rule's effective date passes — there
  is no opt-out.
- Carries criminal penalties for material false statements (18 U.S.C. §1001)
  and statutory enforcement via subpoena under 6 U.S.C. §681d.
- Cannot be substituted by the FedRAMP 1-hour notice, even though both go to
  CISA. The two reports use different schemas and different intake channels.

Operationally, the FedRAMP CSP's incident-response workflow has been
**1 hour → FedRAMP + CISA-attack-vector + agencies**. After CIRCIA Final Rule
effective date it becomes **1 hour → FedRAMP + CISA-attack-vector + agencies,
+ 72 hours → CISA CIRCIA report, + 24 hours → CIRCIA ransom report (if any)**.

---

## 2. Final Rule effective date + reporting deadlines

### 2.1 Effective date arithmetic

The Final Rule is **published May 2026** and per CIRCIA §681c(b) takes effect
**18 months after publication** unless CISA shortens the window in the rule
text. Industry tracking suggests CISA will use the full 18 months, yielding an
effective date of approximately **November 2027**.

> "Note: the effective date is what the operator MUST confirm before the
> tracker fires CIRCIA timers in production. Until the effective date, the
> tracker tracks CIRCIA-eligible incidents but flags them as
> `status: pre-effective-date`. After the effective date, the same incident
> records start the 72-hour clock."

Per CSP, the operator records the confirmed effective date in
`org-profile.yaml` under `incident_response.circia_effective_date` (ISO 8601).
Before that date the CIRCIA emitter runs in **dry-run mode** — produces the
report packet but withholds the auto-submission and the late-report flag.

### 2.2 The 72-hour covered cyber incident clock

Verbatim from 6 U.S.C. §681b(a)(1)(A):

> "...not later than 72 hours after the covered entity reasonably believes
> that the covered cyber incident has occurred."

Critical reading-points:

1. **Clock starts on REASONABLE BELIEF, not confirmation.** This is earlier
   than most other federal reporting clocks. The CIRCIA NPRM preamble
   clarifies that "reasonable belief" is a lower threshold than the SEC 8-K
   "materiality determination" or the HIPAA "Breach Discovery".
2. **The clock is 72 wall-clock hours.** Not business hours. Not 3 business
   days. The NPRM was explicit: 72 hours from reasonable belief, including
   weekends, including holidays.
3. **Late reporting is itself reportable** — the late-report metadata field
   triggers a CISA inquiry but does not absolve the original duty.
4. **No tolling for ongoing investigation.** Even if forensic analysis is
   incomplete, the 72h report goes in with the best available information.
   Supplemental reports fill in details later (per §681b(a)(3)).

For LOOP-G.G2-CIRCIA-EXTENSION, the tracker `circia_incidents` table records
both `discovered_at` (the AFR-ICP discovery clock) and
`reasonable_belief_at` (the CIRCIA clock). They are usually within minutes of
each other but can diverge: e.g. the SOC has an indicator of compromise but
hasn't yet decided whether the incident is "covered". The CIRCIA clock starts
when the IR lead checks the "reasonable belief that this is a covered cyber
incident" box in the tracker UI.

### 2.3 The 24-hour ransom payment clock

Verbatim from 6 U.S.C. §681b(a)(2)(A):

> "...not later than 24 hours after the ransom payment has been made."

Critical reading-points:

1. **The clock starts on PAYMENT, not on the ransomware event.** A covered
   entity may decide not to pay (in which case no 24h report is required for
   the payment, but the 72h covered-incident report still applies).
2. **"Ransom payment" includes cryptocurrency and non-cash consideration.**
   The NPRM preamble clarifies that the value of the payment (in USD) and
   the payment medium (BTC / ETH / USDC / fiat / other) are required fields.
3. **A ransom payment by ANY party on behalf of the covered entity counts.**
   So if the covered entity's cyber-insurance carrier makes the payment, the
   covered entity is still on the hook for the 24h report.
4. **Ransom payment for a non-covered cyber incident is STILL reportable.**
   This is a quirk of the statute: even if the underlying ransomware event
   does not meet the "substantial cyber incident" threshold, the payment
   alone triggers a 24h report.

For LOOP-G.G2-CIRCIA-EXTENSION, the tracker `circia_ransom_payments` table
holds: `incident_id` (link to `circia_incidents` if applicable, else null),
`payment_amount_usd`, `payment_medium`, `paid_at`, `payer_party`,
`recipient_address`, `reported_to_cisa_at`.

### 2.4 Supplemental-report cadence

Verbatim from 6 U.S.C. §681b(a)(3):

> "A covered entity shall promptly submit to the Director an update or
> supplement to a previously submitted covered cyber incident report if
> substantial new or different information becomes available..."

"Promptly" is not defined statutorily. The NPRM proposed an interpretive
floor of 24 hours after the new/different information becomes available.
For LOOP-G.G2-CIRCIA-EXTENSION:

- The tracker fires a `supplemental_due` notification when ANY of:
  `pii_count`, `affected_individual_count`, `attack_vector`, `root_cause`,
  `mitigation_steps`, `breach_duration`, `attacker_attribution` change after
  the initial 72h report.
- The supplemental clock is 24h from the change, measured in wall-clock
  time, until the incident is marked `status: concluded`.

### 2.5 Records retention (2 years)

Per the NPRM and Final Rule's records-retention provision (§225.16 of the
proposed rule text), a covered entity must preserve all data relevant to the
covered cyber incident or ransom payment for **at least 2 years** following
the date of submission of the final supplemental report. This includes:

- Communications data (emails, chat logs, phone records related to the
  incident).
- Forensic data (system images, memory dumps, log files).
- Indicators of compromise (file hashes, IP addresses, domain names).
- Vulnerability details and exploitation evidence.
- Internal analysis, reports, and decision rationale.
- The covered cyber incident report itself and all supplemental reports.

LOOP-G.G2-CIRCIA-EXTENSION adds a `circia_retention_until` field to the
`circia_incidents` table, populated as `final_report_at + 2y`. The tracker
emits a cleanup-eligible audit event AFTER `retention_until` only — never
before.

---

## 3. "Covered Entity" determination

### 3.1 The two-prong test

A "covered entity" is, per the NPRM and Final Rule:

1. An **entity in a critical infrastructure sector** as defined by
   Presidential Policy Directive 21 (PPD-21, Feb 12, 2013).
2. That **exceeds the SBA small-business size standard** for its NAICS code.

### 3.2 The 16 critical infrastructure sectors (PPD-21)

Per https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience/critical-infrastructure-sectors :

| # | Sector | Sector Risk Management Agency (SRMA) |
|---|---|---|
| 1 | Chemical | CISA |
| 2 | Commercial Facilities | CISA |
| 3 | Communications | CISA |
| 4 | Critical Manufacturing | CISA |
| 5 | Dams | CISA |
| 6 | Defense Industrial Base | DoD |
| 7 | Emergency Services | CISA |
| 8 | Energy | DoE |
| 9 | Financial Services | Treasury |
| 10 | Food and Agriculture | USDA + HHS |
| 11 | Government Facilities | DHS + GSA |
| 12 | Healthcare and Public Health | HHS |
| 13 | Information Technology | CISA |
| 14 | Nuclear Reactors, Materials, and Waste | DHS + NRC |
| 15 | Transportation Systems | DHS + DOT |
| 16 | Water and Wastewater Systems | EPA |

A FedRAMP-authorized CSP that serves federal customers almost always
qualifies as a covered entity under **Sector 11 (Government Facilities)** —
because the federal-customer relationship places the CSP in support of
government operations — and frequently under **Sector 13 (Information
Technology)** independently.

### 3.3 The SBA small-business carve-out

The NPRM proposed two parallel definitions of "covered entity":

- Any entity in a critical infrastructure sector that **exceeds the small
  business size standard** for its primary NAICS code (per SBA's published
  size standards).
- Plus a list of **sector-based criteria** that capture entities the SBA
  size standard alone would miss (e.g. any entity that owns/operates
  Industrial Control Systems, regardless of SBA size).

For SaaS CSPs the primary NAICS code is typically **518210 (Data Processing,
Hosting, and Related Services)** with an SBA size standard of **$47 million
annual revenue**, or **541512 (Computer Systems Design Services)** at
**$34 million**. Most FedRAMP CSPs exceed these thresholds. Very small
"FedRAMP Tailored Li-SaaS" CSPs may fall below — they document the SBA-size
carve-out in `org-profile.yaml` under `circia.sba_carveout_rationale`.

### 3.4 LOOP-G.G2-CIRCIA-EXTENSION decision logic

The tracker `circia_covered_entity_assessment` table holds the per-CSP
determination:

```sql
CREATE TABLE circia_covered_entity_assessment (
  id TEXT PRIMARY KEY,
  system_id TEXT NOT NULL,
  ppd21_sector TEXT NOT NULL CHECK (ppd21_sector IN (
    'chemical','commercial_facilities','communications','critical_manufacturing',
    'dams','defense_industrial_base','emergency_services','energy',
    'financial_services','food_and_agriculture','government_facilities',
    'healthcare_public_health','information_technology','nuclear_reactors',
    'transportation_systems','water_wastewater'
  )),
  primary_naics_code TEXT NOT NULL,
  sba_size_standard_usd INTEGER NOT NULL,
  annual_revenue_usd INTEGER NOT NULL,
  sba_size_exceeded INTEGER NOT NULL CHECK (sba_size_exceeded IN (0,1)),
  sector_specific_criterion_triggered INTEGER NOT NULL CHECK (sector_specific_criterion_triggered IN (0,1)),
  covered_entity_determination INTEGER NOT NULL CHECK (covered_entity_determination IN (0,1)),
  rationale TEXT NOT NULL,
  determined_at TEXT NOT NULL,
  determined_by_user_id TEXT NOT NULL,
  signature TEXT NOT NULL,
  signing_key_id TEXT NOT NULL
);
```

The operator completes this once, signs it, and the tracker uses
`covered_entity_determination = 1` as the gate for all CIRCIA workflows.
If `0`, the tracker still tracks incidents in `circia_incidents` but
flags them `status: not-covered-entity` and skips the 72h clock.

REO compliance: the determination is operator-signed; the system never
auto-decides covered-entity status.

---

## 4. "Covered Cyber Incident" definition

### 4.1 The statutory definition

Per 6 U.S.C. §681(4):

> "The term 'covered cyber incident' means a substantial cyber incident
> experienced by a covered entity that satisfies the definition and criteria
> established by the Director in the final rule issued pursuant to section
> 681c(b) of this title."

So the definition is recursive: a covered cyber incident is a *substantial*
cyber incident, where "substantial" is defined by the Final Rule.

### 4.2 The NPRM "substantial cyber incident" four-prong test

Per 89 FR 23644 (NPRM), a substantial cyber incident is one that leads to:

> "(1) Substantial loss of confidentiality, integrity, or availability of a
> covered entity's information system or network; OR
> (2) Serious impact on the safety and resiliency of a covered entity's
> operational systems and processes; OR
> (3) Disruption of a covered entity's ability to engage in business or
> industrial operations, or deliver goods or services; OR
> (4) Unauthorized access to a covered entity's information system or
> network, or any nonpublic information contained therein, that is facilitated
> through or caused by either a compromise of a cloud service provider,
> managed service provider, other third-party data hosting provider, or a
> supply chain compromise."

Each prong is independently sufficient. For a SaaS CSP, prong (4) is
particularly relevant because:

- If the CSP itself is compromised, all CSP-hosted federal customer data is
  subject to the (4) test from the *customer's* perspective (the customer is
  the covered entity — but the CSP shoulders the operational reporting
  load).
- If the CSP's upstream subprocessor is compromised, prong (4) triggers for
  the CSP via "supply chain compromise" or "third-party data hosting
  provider".

### 4.3 NPRM exclusions (what is NOT a covered cyber incident)

Per the NPRM preamble:

- Cyber incidents in good-faith research environments (test/dev).
- Lawful US-government activity (DoD red-team exercises, etc.).
- Threats and reconnaissance that did NOT culminate in substantial loss.
- Singleton malware infections quickly contained without prong (1)-(4)
  impact (e.g. a contained workstation compromise with no lateral movement
  and no data exfiltration).

### 4.4 LOOP-G.G2-CIRCIA-EXTENSION classifier

The tracker `circia_incidents.is_covered_cyber_incident` field is operator-
decided in the UI via a 4-prong checklist:

```
☐ Prong 1: Substantial loss of confidentiality, integrity, or availability
☐ Prong 2: Serious impact on safety / resiliency of operational systems
☐ Prong 3: Disruption of business/industrial operations or service delivery
☐ Prong 4: Unauthorized access via CSP/MSP/3rd-party-host/supply-chain compromise
```

If ANY prong is checked AND `covered_entity_determination = 1`, the 72h
clock starts. The 4-prong rationale is required and signed.

REO compliance: classifier SUGGESTS prong 1 when AFR-ICP `severity` is
`high` or `critical`, but operator must explicitly check the prong box.

---

## 5. Required data fields (per the Final Rule)

The NPRM enumerated 10 categories of required fields, all of which carry
forward to the Final Rule. The LOOP-G.G2-CIRCIA-EXTENSION
`circia_report.json` schema enforces every field.

### 5.1 Categories of required fields

| # | Category | Subfields (illustrative) |
|---|---|---|
| 1 | **Covered Entity Identifying Info** | legal name, DUNS/UEI, primary NAICS, address, point-of-contact name + role + phone + email |
| 2 | **Incident Description** | high-level narrative, discovery method, timeline, IR lead |
| 3 | **Affected Systems** | system identifiers (mapped to CSO inventory), data types involved, federal-customer impact |
| 4 | **Vulnerabilities Exploited** | CVE IDs, CWE classifications, configuration weaknesses, zero-day flag |
| 5 | **TTPs (Tactics, Techniques, Procedures)** | MITRE ATT&CK tactic+technique+procedure IDs, attacker behaviors observed |
| 6 | **Indicators of Compromise (IOCs)** | file hashes (MD5/SHA-1/SHA-256), IP addresses, domain names, URLs, registry keys, mutexes |
| 7 | **Impact Assessment** | which prong(s) of substantial-cyber-incident definition; quantitative loss estimates |
| 8 | **Mitigation Actions** | containment + eradication + recovery actions taken or planned |
| 9 | **Attribution** | attacker identity, if known; nation-state, criminal, insider, hacktivist |
| 10 | **Other Federal Reports** | enumeration of other agencies notified (FBI, SEC, FedRAMP, agency customers, etc.) and report identifiers |

### 5.2 Ransom-payment-specific fields (additional to the above)

| # | Field | Notes |
|---|---|---|
| R1 | `payment_amount_usd` | USD-equivalent at the time of payment |
| R2 | `payment_medium` | BTC / ETH / USDC / fiat / other |
| R3 | `payment_crypto_address` | recipient wallet address |
| R4 | `paid_at` | ISO 8601 (RFC 3339) |
| R5 | `payer_party` | covered entity / insurance carrier / 3rd-party negotiator |
| R6 | `negotiation_party` | covered entity / insurance carrier / negotiator firm |
| R7 | `attacker_demand_initial` | initial ransom demand amount |
| R8 | `attacker_demand_final_paid` | paid amount may differ from initial demand |
| R9 | `decryption_outcome` | provided / partial / not provided |
| R10 | `data_returned` | yes / no / partial / unknown |

### 5.3 LOOP-G.G2-CIRCIA-EXTENSION JSON envelope

```json
{
  "circia_report_id": "<uuid>",
  "report_type": "covered_cyber_incident | ransom_payment | supplemental",
  "submission_clock_started_at": "<RFC 3339>",
  "submission_clock_deadline_at": "<RFC 3339>",
  "covered_entity": {
    "legal_name": "...",
    "duns_or_uei": "...",
    "primary_naics": "518210",
    "address": "...",
    "poc": { "name": "...", "role": "...", "phone": "...", "email": "..." }
  },
  "incident": {
    "narrative": "...",
    "discovered_at": "<RFC 3339>",
    "reasonable_belief_at": "<RFC 3339>",
    "ir_lead": "...",
    "is_covered_cyber_incident": true,
    "prongs_triggered": [1, 4],
    "prong_rationale": "..."
  },
  "affected_systems": [
    { "asset_id": "...", "system_name": "...", "data_types": [...], "federal_customer_impact": [...] }
  ],
  "vulnerabilities": [
    { "cve_id": "CVE-2026-XXXX", "cwe": "CWE-79", "zero_day": false, "patch_status": "patched 2026-05-12" }
  ],
  "ttps": [
    { "mitre_tactic": "TA0001", "mitre_technique": "T1190", "mitre_procedure": "P####", "description": "..." }
  ],
  "iocs": {
    "file_hashes": [{ "algo": "sha256", "value": "..." }],
    "ip_addresses": ["..."],
    "domains": ["..."],
    "urls": ["..."]
  },
  "impact": {
    "prong_1_substantial_loss": { "triggered": true, "rationale": "...", "estimate_usd": 0 },
    "prong_2_safety_resilience": { "triggered": false },
    "prong_3_business_disruption": { "triggered": false },
    "prong_4_supply_chain": { "triggered": true, "rationale": "..." }
  },
  "mitigation": {
    "containment_actions": [...],
    "eradication_actions": [...],
    "recovery_actions": [...]
  },
  "attribution": {
    "attacker_class": "criminal | nation_state | insider | hacktivist | unknown",
    "specific_attribution": "...",
    "confidence": "low | moderate | high"
  },
  "other_federal_reports": [
    { "agency": "FedRAMP PMO", "report_id": "...", "submitted_at": "..." },
    { "agency": "FBI", "report_id": "...", "submitted_at": "..." }
  ],
  "ransom_payment": null,
  "provenance": {
    "emitter": "core/circia-report.ts",
    "emittedAt": "<RFC 3339>",
    "sourceCalls": ["tracker:circia_incidents:read", "afr-icp:incident:read"],
    "signingKeyId": "...",
    "runId": "..."
  }
}
```

REO compliance: every field traces to either tracker-DB data (operator-
entered + auth-stamped) or AFR-ICP data (already operator-stamped). No
field is auto-fabricated.

---

## 6. Submission mechanism

### 6.1 The official CISA submission channel

Per CISA's CIRCIA page (https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia)
and the Final Rule, the official submission channels are:

1. **CISA CIRCIA Web Form** (primary) — a structured intake form at the
   CISA portal. URL canonical: tracked in
   `org-profile.yaml::incident_response.circia.submission_url`. The Final
   Rule does NOT publish a fixed URL in the rule text — CISA reserves the
   right to update the URL through guidance. As of June 2026 the operational
   URL is at `https://www.cisa.gov/forms/report` (general incident reporting
   form, which routes to the CIRCIA intake after the effective date).
2. **CISA CIRCIA API** (planned but not yet live as of June 2026).
3. **CISA-Approved Third-Party Submission Service** (per §681b(a)(7) — a
   covered entity may use a vetted commercial submitter; the covered entity
   retains the legal duty).

For LOOP-G.G2-CIRCIA-EXTENSION, the tracker:

- Generates the `circia-report.json` packet locally (signed Ed25519 +
  RFC 3161 timestamp).
- Renders a human-reviewable PDF preview via `core/circia-report-pdf.ts`
  (deterministic PDF emission).
- Offers a one-click "Submit to CISA" button that:
  - In **manual mode**: opens the CISA web form pre-populated with the
    packet via clipboard or browser-fill helper (operator confirms +
    submits in the browser).
  - In **API mode** (post-API launch): POSTs the packet to the CISA API
    with the operator's CISA-issued submission token; captures the
    response token + receipt timestamp.

### 6.2 Submission acknowledgement capture

Once CISA accepts the report, CISA returns an **acknowledgement token**
(per the Final Rule §225.10(c) acknowledgement provision). The tracker
records:

```sql
CREATE TABLE circia_submission_receipts (
  id TEXT PRIMARY KEY,
  circia_report_id TEXT NOT NULL REFERENCES circia_incidents(circia_report_id),
  submitted_at TEXT NOT NULL,
  submitted_by_user_id TEXT NOT NULL,
  submission_channel TEXT NOT NULL CHECK (submission_channel IN ('web_form_manual','api','third_party_submitter')),
  cisa_acknowledgement_token TEXT,
  cisa_receipt_at TEXT,
  cisa_assigned_incident_id TEXT,
  signature TEXT NOT NULL,
  signing_key_id TEXT NOT NULL
);
```

The acknowledgement token is the single authoritative artifact proving the
72h or 24h clock was met. REO: the token comes from CISA, not from the
system; if the operator hasn't pasted it in within 24h of submission, the
tracker raises a `circia_receipt_missing` diagnostic.

### 6.3 Differences from DFARS DIBNet

CIRCIA submissions go to CISA. DFARS 252.204-7012 submissions go to **DIBNet**
(https://dibnet.dod.mil/). They are separate intakes — a CSP supporting both
federal civilian and DoD customers may have to report to BOTH, with the same
underlying incident, in the same 72h window. LOOP-S.S3 covers the DIBNet
side; LOOP-G.G2-CIRCIA-EXTENSION covers the CISA side. The tracker
`incident_reports` view shows both submissions side-by-side per incident.

---

## 7. Integration with LOOP-G.G2 (AFR-ICP) and LOOP-M.M4 (privacy IRP)

### 7.1 Integration with LOOP-G.G2 (AFR-ICP)

AFR-ICP enforces the 1-hour FedRAMP, 1-hour agency, and 1-hour CISA-attack-
vector clocks. CIRCIA adds the 72-hour CISA covered-cyber-incident clock
and the 24-hour ransom-payment clock. They coexist:

- An incident enters AFR-ICP first (1-hour FedRAMP notice fires immediately
  on tracker incident creation).
- Within the first hour, the IR lead is prompted in the tracker:
  - Is this a "covered cyber incident" under CIRCIA? (4-prong checklist)
  - Did we make a ransom payment? (separate workflow)
- If the operator marks "covered cyber incident", the CIRCIA 72-hour timer
  starts from the **reasonable_belief_at** timestamp (often within minutes
  of `discovered_at`).
- If the operator marks "ransom payment made", a separate 24-hour timer
  starts from `paid_at`.
- The supplemental-report cadence enforcer runs once per hour, looking for
  changes in tracked fields and raising `supplemental_due` events.

LOOP-G.G2-CIRCIA-EXTENSION extends `core/afr-icp.ts` with a hook
`assessCircia(incident): CircaiClassification` that the AFR-ICP UI calls
right after incident creation. The classification is operator-decided.

### 7.2 Integration with LOOP-M.M4 (privacy IRP)

Most CIRCIA-covered cyber incidents involve PII because federal-customer
data routinely contains PII. The M.M4-CIRCIA-EXTENSION slice covers the
intersection:

- The harm-risk assessment under OMB M-17-12 §V is computed in M.M4.
- The CIRCIA report's `affected_systems` and `impact` fields cross-reference
  the M.M4 `privacy_incidents.affected_individual_count` and
  `pii_categories` fields.
- The 60-day individual notification under OMB M-17-12 §VI runs in parallel
  to the 72-hour CIRCIA report; they do not substitute for each other.

The M.M4-CIRCIA-EXTENSION slice adds `privacy_incidents.circia_report_id`
(FK to the CIRCIA report) so an analyst can navigate between the two
incident views in one click.

### 7.3 Order of operations when an incident hits all three frameworks

Worst case: a SaaS CSP discovers a database compromise affecting federal-
customer PII, with a ransom note left behind. Within the first 24 hours:

1. **T+0:** SOC creates AFR-ICP incident (LOOP-G.G2).
2. **T+5 min:** 1-hour clocks start: FedRAMP, agencies, CISA-attack-vector.
3. **T+15 min:** Operator triages — confirms covered cyber incident (CIRCIA
   72h clock starts), PII implicated (M.M4 workflow starts).
4. **T+30 min:** SAOP notified (M.M4 step), CISA US-CERT report (1h), FedRAMP
   email (1h), agency contacts (1h).
5. **T+1 h:** AFR-ICP 1h SLA met. Daily-update cadence enforcer engaged.
6. **T+6 h:** Insurance carrier authorizes ransom payment. Operator records
   payment in `circia_ransom_payments`. CIRCIA 24h ransom clock starts.
7. **T+24 h:** Insurance carrier pays. CIRCIA ransom report due 24h after
   payment (T+48 h).
8. **T+48 h:** CIRCIA ransom report submitted to CISA. Acknowledgement token
   captured.
9. **T+60 h:** Forensic analysis complete; root cause known.
10. **T+72 h:** CIRCIA covered-cyber-incident report submitted to CISA.
    Acknowledgement token captured. Late-flag NOT triggered.
11. **T+96 h:** Substantial new info: attribution to APT group identified.
    Supplemental report 24h clock starts.
12. **T+120 h:** Supplemental report submitted.
13. **T+60 d:** Individual notifications go out under M-17-12 §VI.
14. **T+resolved:** Final supplemental + concluded marker.
15. **T+resolved + 2y:** CIRCIA retention period expires.

The tracker timeline view renders this as a single coherent timeline with
all the timer milestones visible.

---

## 8. Integration with tracker DB

### 8.1 New tables (additive to existing schema)

```sql
-- Operator's covered-entity determination (signed, immutable per assessment)
CREATE TABLE circia_covered_entity_assessment ( /* see §3.4 */ );

-- One row per CIRCIA-eligible incident
CREATE TABLE circia_incidents (
  circia_report_id TEXT PRIMARY KEY,
  afr_icp_incident_id TEXT REFERENCES icp_incidents(id),
  privacy_incident_id TEXT REFERENCES privacy_incidents(uuid),
  discovered_at TEXT NOT NULL,
  reasonable_belief_at TEXT NOT NULL,
  is_covered_cyber_incident INTEGER NOT NULL CHECK (is_covered_cyber_incident IN (0,1)),
  prongs_triggered TEXT NOT NULL,  -- JSON array of [1,2,3,4] subset
  prong_rationale TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open','reported','supplemental_pending','concluded')),
  initial_report_due_at TEXT NOT NULL,   -- reasonable_belief_at + 72h
  initial_report_submitted_at TEXT,
  cisa_acknowledgement_token TEXT,
  final_report_at TEXT,
  retention_until TEXT,
  created_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  signature TEXT NOT NULL,
  signing_key_id TEXT NOT NULL
);

-- One row per ransom payment (may exist without a covered-cyber-incident parent)
CREATE TABLE circia_ransom_payments (
  id TEXT PRIMARY KEY,
  circia_report_id TEXT REFERENCES circia_incidents(circia_report_id),
  paid_at TEXT NOT NULL,
  payment_amount_usd INTEGER NOT NULL,
  payment_medium TEXT NOT NULL,
  payment_crypto_address TEXT,
  payer_party TEXT NOT NULL,
  initial_demand_amount INTEGER,
  decryption_outcome TEXT,
  data_returned TEXT,
  ransom_report_due_at TEXT NOT NULL,   -- paid_at + 24h
  ransom_report_submitted_at TEXT,
  cisa_acknowledgement_token TEXT,
  created_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  signature TEXT NOT NULL,
  signing_key_id TEXT NOT NULL
);

-- One row per submission receipt
CREATE TABLE circia_submission_receipts ( /* see §6.2 */ );

-- One row per supplemental report
CREATE TABLE circia_supplemental_reports (
  id TEXT PRIMARY KEY,
  circia_report_id TEXT NOT NULL REFERENCES circia_incidents(circia_report_id),
  triggering_change TEXT NOT NULL,   -- which field changed
  supplemental_due_at TEXT NOT NULL, -- change_at + 24h
  supplemental_submitted_at TEXT,
  cisa_acknowledgement_token TEXT,
  created_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  signature TEXT NOT NULL
);
```

### 8.2 Timer enforcement (cron + idle)

The tracker `scripts/circia-timers.ts` daemon runs hourly:

- For every `circia_incidents` with `status IN ('open','reported','supplemental_pending')`:
  - Compute `time_until_due = initial_report_due_at - now()`.
  - If `time_until_due < 24h AND initial_report_submitted_at IS NULL`:
    raise audit event `circia_72h_warning` + notify on-call.
  - If `time_until_due < 0 AND initial_report_submitted_at IS NULL`:
    raise audit event `circia_72h_breach` + escalate to compliance.
- For every `circia_ransom_payments` with `ransom_report_submitted_at IS NULL`:
  - Symmetric warning at < 8h + breach at < 0.
- For every `circia_supplemental_reports` with `supplemental_submitted_at IS NULL`:
  - Symmetric warning at < 6h + breach at < 0.

REO compliance: timer math uses real `paid_at` / `reasonable_belief_at`
timestamps; the system never back-dates. The breach event is INFORMATIONAL,
not auto-submitting — humans submit.

### 8.3 Records retention enforcement

A separate `scripts/circia-retention-sweep.ts` daemon runs daily:

- For every `circia_incidents` with `retention_until < now()`:
  - List all linked data (afr-icp incident, privacy incident, IOCs, etc.).
  - Emit a `circia_retention_eligible` audit event with the list.
  - Do NOT delete — deletion is operator action.
- For every `circia_incidents` with `retention_until > now()`:
  - Skip.

REO compliance: the system never auto-deletes incident data. Deletion is a
documented operator action with sign-off.

---

## 9. Cross-references with other federal reporting frameworks

### 9.1 The federal cyber-reporting landscape

A FedRAMP CSP serving multiple federal customers may face reporting
obligations under several frameworks for the same incident. CIRCIA was
intentionally designed by Congress to drive harmonization — see §681e
(Harmonization with other reporting requirements). Until full harmonization
ratifies, the CSP must submit redundant reports.

| Framework | Trigger | Clock | Submission channel | LOOP-X |
|---|---|---|---|---|
| **FedRAMP ICP-CSX-IRF** | Incident affecting FedRAMP-authorized system | 1h | email to fedramp_security@fedramp.gov | LOOP-G.G2 |
| **FedRAMP ICP-CSX-IRA** | Same | 1h | per-agency contacts | LOOP-G.G2 |
| **FedRAMP ICP-CSX-IRC** | CISA-attack-vector applies | 1h | https://myservices.cisa.gov/irf | LOOP-G.G2 |
| **CIRCIA covered cyber incident** | Substantial cyber incident; covered entity | 72h | CISA CIRCIA portal | LOOP-G.G2.CIRCIA |
| **CIRCIA ransom payment** | Ransom payment made | 24h | CISA CIRCIA portal | LOOP-G.G2.CIRCIA |
| **DFARS 252.204-7012** | Cyber incident on CDI/CUI in DoD contract | 72h | https://dibnet.dod.mil/ | LOOP-S.S3 |
| **HIPAA Breach Notification** | PHI breach | 60d to individuals, 60d to HHS (or sooner) | HHS portal + individuals | not in scope (LOOP-M overlay for partner-handled PHI) |
| **SEC 8-K Item 1.05** | Material cybersecurity incident (public co.) | 4 business days from materiality determination | EDGAR | in scope for any CSP that is publicly traded, a wholly-owned subsidiary of a publicly-traded parent, or pre-IPO with cyber-disclosure obligations to investors. See docs/slices/G/G.G2-SEC-8K-EXTENSION.md |
| **FCC Section 4(j) Breach Reporting** | CPNI breach | 7 business days | FCC + Secret Service / FBI | not in scope |
| **NCUA Cyber Incident Notification** | Credit-union cyber incident | 72h | NCUA portal | not in scope (CSP customers may carry this duty) |
| **GLBA Safeguards Rule §314.4(j)** | Customer-info breach affecting ≥500 customers | 30d to FTC | FTC portal | not in scope (financial-services customers carry this) |
| **EU NIS2 Article 23** | Significant incident (EU-customer-facing CSP) | 24h early warning + 72h notification + 1m final | per-Member-State CSIRT | not in scope (US-focused at MVP) |
| **OMB M-17-12 (privacy breach)** | PII breach at FCEB agency | 1h to CISA US-CERT; 60d individuals; 7d Congress (major) | varies | LOOP-M.M4 |

> **Reclassification (2026-06-07):** SEC Form 8-K Item 1.05 was originally classified as "not in scope" on the assumption that the CSP is rarely a publicly-traded company directly. This is incorrect for CSPs that are publicly traded, are wholly-owned subsidiaries of publicly-traded parents, or are pre-IPO with cyber-disclosure obligations to investors. SEC Final Rule 33-11216 (Jul 26, 2023) imposes a 4-business-day disclosure clock from materiality determination on any registrant that experiences a material cybersecurity incident. The full extension specification is in [docs/slices/G/G.G2-SEC-8K-EXTENSION.md](slices/G/G.G2-SEC-8K-EXTENSION.md), which integrates the SEC 8-K clock with the CIRCIA 72-hour clock and DFARS 7012 72-hour clock as a multi-disclosure coordination sequence.

### 9.2 Harmonization status (§681e)

§681e directs CISA to coordinate with other federal regulators to reduce
duplication. As of June 2026 no harmonization rule has been published. The
DHS Cyber Incident Reporting Council was established under §681f and is
working on reducing the reporting burden. For now, every framework above
must be assumed independent.

LOOP-G.G2-CIRCIA-EXTENSION emits a `other_federal_reports[]` field on every
CIRCIA report that lists all other federal reports submitted for the same
incident, so CISA's harmonization analysis has the data it needs.

### 9.3 The "substantially similar information" safe harbor

§681b(a)(5)(B) provides a partial safe harbor: a covered entity that
submits "substantially similar information" to another federal agency
under a separate reporting requirement, and that agency has an information-
sharing agreement with CISA, is NOT required to also submit to CISA. As of
June 2026 the agreements covered: the EPA Water Sector reporting program.
For most CSPs the safe harbor does NOT apply.

LOOP-G.G2-CIRCIA-EXTENSION's `circia_incidents.safe_harbor_invoked` field
captures the operator's claim with rationale. Default is `false`.

---

## 10. REO compliance notes

CIRCIA workflow follows the same REO standard as the rest of cloud-evidence:

- **Operator-supplied data:** Covered-entity determination, prong selection,
  CISA acknowledgement tokens, ransom-payment fields. All signed.
- **Tracker-DB-sourced data:** Incident metadata, IOCs, mitigation steps,
  TTPs. All operator-entered + auth-stamped.
- **AFR-ICP-derived data:** Cross-reference to `icp_incidents.discovered_at`
  + `severity` + `attack_vector`. Single source of truth.
- **M.M4-derived data:** `pii_categories`, `affected_individual_count`,
  `harm_risk`. Single source of truth.
- **Allowed fixed data (per CLAUDE.md Rule 3):** PPD-21 16-sector list, SBA
  size-standard NAICS codes (published by SBA), 6 U.S.C. citation strings,
  the 72h and 24h statutory clocks themselves.
- **Provenance block:** Every emitted CIRCIA artifact carries `provenance`
  with `emitter`, `emittedAt`, `sourceCalls`, `signingKeyId`, `runId`.
- **Signing:** Every `circia-report.json` is Ed25519-signed and RFC-3161
  timestamped via `core/sign.ts`.
- **No auto-submission:** The system never submits to CISA on its own; the
  operator clicks "Submit" in the tracker UI and pastes the acknowledgement
  token back in.

---

## 11. Open questions tracked here (cross-cutting)

These are decision-bearing questions the operator must resolve before the
CIRCIA workflow can ship to production. They are also reflected in the
slice-level docs.

1. **Effective date confirmation.** Operator confirms the CIRCIA Final
   Rule's effective date in `org-profile.yaml` so the tracker fires 72h
   timers only at the right time.
2. **Covered-entity determination.** Operator signs the 16-sector + SBA-
   size determination; the system never auto-decides.
3. **Submission channel.** Web form (manual) vs. API (when live) vs.
   third-party submitter. Operator picks.
4. **Other-federal-reports list maintenance.** Which other frameworks does
   this CSP report under? (DFARS? HIPAA-overlay via partner? NCUA-overlay
   via customer?) Operator enumerates in `org-profile.yaml`.
5. **Safe-harbor invocation.** If operator believes "substantially similar"
   information was submitted elsewhere, the safe-harbor claim + rationale
   are signed.
6. **CISA acknowledgement token capture cadence.** How quickly after
   submission must the operator paste the token back? Recommend within 24h
   of submission; tracker raises diagnostic at 24h.
7. **Records-retention sweep cadence.** Daily vs. weekly. Recommend daily
   for retention eligibility, with operator-initiated deletion.
8. **Ransom-payment workflow restriction.** Should the tracker prevent
   recording a ransom payment until the operator has consulted legal? (OFAC
   sanctions implications — paying a sanctioned entity is a separate crime.)
   Recommend a gating checkbox in the UI: "I have consulted legal counsel
   on OFAC implications".

---

## 12. References (full source URL map)

- CIRCIA statute: https://www.govinfo.gov/content/pkg/COMPS-15425/pdf/COMPS-15425.pdf
- CIRCIA NPRM (89 FR 23644, 2024-04-04): https://www.federalregister.gov/documents/2024/04/04/2024-06526/cyber-incident-reporting-for-critical-infrastructure-act-circia-reporting-requirements
- CISA CIRCIA topic page: https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia
- CISA CIRCIA FAQ: https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/circia/faqs
- CIRCIA Town Hall (91 FR ##, 2026-02-13): https://www.federalregister.gov/documents/2026/02/13/2026-02948/cyber-incident-reporting-for-critical-infrastructure-act-circia-rulemaking-town-hall-meetings
- CISA general incident reporting form: https://www.cisa.gov/forms/report
- PPD-21 critical infrastructure sectors: https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience/critical-infrastructure-sectors
- DFARS 252.204-7012: https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting
- DIBNet: https://dibnet.dod.mil/
- SBA size standards: https://www.sba.gov/document/support-table-size-standards
- MITRE ATT&CK: https://attack.mitre.org/
- 18 U.S.C. §1001 (false statements): https://www.govinfo.gov/content/pkg/USCODE-2023-title18/pdf/USCODE-2023-title18-partI-chap47-sec1001.pdf
- DHS Cyber Incident Reporting Council: https://www.dhs.gov/CIRCIA
- Industry tracking (CIRCIA Final Rule date):
  - https://www.dwt.com/blogs/privacy--security-law-blog/2025/09/cisa-delays-cyber-incident-reporting-rules-2026
  - https://www.fisherphillips.com/en/insights/insights/new-federal-cybersecurity-reporting-rules-are-on-their-way

---

## Appendix A — Glossary

- **CIRCIA:** Cyber Incident Reporting for Critical Infrastructure Act of
  2022, Div Y of PL 117-103.
- **Covered Cyber Incident:** A substantial cyber incident at a covered
  entity, per 6 U.S.C. §681(4).
- **Covered Entity:** An entity in a PPD-21 critical infrastructure sector
  that exceeds SBA small-business thresholds or meets a sector-specific
  criterion.
- **Substantial Cyber Incident:** A cyber incident meeting one of the four
  prongs defined in the NPRM / Final Rule.
- **Ransom Payment:** Any payment made in response to a ransomware attack,
  in cash, cryptocurrency, or non-cash consideration.
- **PPD-21:** Presidential Policy Directive 21 (Critical Infrastructure
  Security and Resilience), Feb 12, 2013.
- **NPRM:** Notice of Proposed Rulemaking, the April 2024 Federal Register
  document.
- **Final Rule:** The May 2026 codified rule.
- **CISA:** Cybersecurity and Infrastructure Security Agency.
- **Acknowledgement Token:** The receipt CISA returns on accepted submission.
- **Safe Harbor:** §681b(a)(5)(B) partial exemption when substantially
  similar information has been submitted elsewhere.
- **Effective Date:** The date the Final Rule's reporting duties become
  enforceable (per the Final Rule's own text + 18-month statutory window).
- **Supplemental Report:** A follow-up to the 72h initial report when
  substantially new or different information emerges.
- **DIBNet:** The DoD Defense Industrial Base Network reporting portal for
  DFARS 252.204-7012 submissions (parallel to CIRCIA).
- **PPD-21 Sector 13 (IT):** Information Technology sector under PPD-21,
  the most common sector designation for SaaS CSPs.
- **PPD-21 Sector 11 (Government Facilities):** Sector under PPD-21 that
  applies to entities supporting government operations, including FedRAMP
  CSPs serving federal customers.

---

## Appendix B — Frequency of CIRCIA reports per typical FedRAMP CSP

Based on FedRAMP PMO incident-disclosure statistics and DHS Cyber Incident
Reporting Council estimates:

- **0-1 covered cyber incidents per year** at a typical mid-market FedRAMP
  CSP (most "incidents" don't meet the substantial-cyber-incident threshold).
- **<1 ransom payment per year** (most CSPs do not pay ransom).
- **3-5 supplemental reports** per covered cyber incident (initial info is
  incomplete; details emerge over weeks).

The tracker UI is built around the assumption that CIRCIA workflow is
rare-but-high-stakes. Optimisation targets are correctness + auditability,
not throughput.

---

## Appendix C — Test taxonomy for CIRCIA workflow

For LOOP-G.G2-CIRCIA-EXTENSION and LOOP-M.M4-CIRCIA-EXTENSION, the test
matrix spans:

1. Clock arithmetic (72h, 24h, supplemental 24h, retention 2y).
2. Covered-entity determination logic (16 sectors × SBA size table).
3. Prong selection (1, 2, 3, 4 individually + combinations).
4. Submission packet schema (all required fields present).
5. Acknowledgement token capture + signing.
6. Safe-harbor invocation + rationale signing.
7. Supplemental-due triggers (which field changes trigger which clock).
8. Retention sweep eligibility (after 2y + final supplemental).
9. AFR-ICP integration (link to icp_incidents).
10. M.M4 integration (link to privacy_incidents + harm risk).
11. Other-federal-reports cross-reference.
12. PDF preview deterministic across runs.
13. JSON packet deterministic + signed.
14. REO compliance: no auto-submission, no auto-decision, no auto-deletion.
15. Late-report detection + diagnostic emission.

Each extension slice doc enumerates the exact test list it owns.

---

## Appendix D — How this document relates to the rest of the corpus

- **`docs/STATUS.md`** — When LOOP-G.G2-CIRCIA-EXTENSION ships, a row is
  added to STATUS.md under the LOOP-G section.
- **`docs/loops/LOOP-G-SPEC.md`** — Cross-references this document from
  the LOOP-G.G2 section.
- **`docs/loops/LOOP-M-SPEC.md`** — Cross-references this document from
  the LOOP-M.M4 section.
- **`docs/slices/G/G.G2.md`** — Base AFR-ICP slice; CIRCIA workflow is
  additive on top.
- **`docs/slices/G/G.G2-CIRCIA-EXTENSION.md`** — The detailed CIRCIA
  extension to G.G2. Reads this document first.
- **`docs/slices/M/M.M4.md`** — Base privacy IRP slice; CIRCIA workflow
  applies when PII is involved.
- **`docs/slices/M/M.M4-CIRCIA-EXTENSION.md`** — The CIRCIA-privacy
  intersection. Reads this document first.
- **`docs/SECOND-PASS-AUDIT.md` §2.6** — Original audit finding that
  triggered CIRCIA workflow inclusion. Ratified 2026-06-07.
- **`docs/GLOSSARY.md`** — CIRCIA, NPRM, PPD-21, DIBNet entries added.

The CIRCIA Final Rule effective date is the next major external dependency
on this corpus.
