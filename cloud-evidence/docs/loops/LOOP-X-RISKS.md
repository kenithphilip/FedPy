---
loop_id: X
title: LOOP-X — Zero Trust Architecture (OMB M-22-09 + NIST SP 800-207 / 800-207A + CISA ZTMM v2.0) risks register
status: pending
applicable_conditional: false
condition: Universally applicable. OMB M-22-09 (Federal Zero Trust Strategy, Jan 26 2022) directs every Federal civilian Executive Branch agency to meet specific zero-trust goals by end of FY24. FedRAMP 20x KSIs and SCN cadence both inherit ZTA expectations. Any CSP whose authorization package will be evaluated under FedRAMP 20x is expected to demonstrate ZTMM maturity per CISA ZTMM v2.0 (Apr 2023). No opt-out exists. The implementation-level `--zero-trust-attestation` flag exists for development convenience; the production orchestrator emits X.X1..X.X7 in every FedRAMP 20x submission build.
trigger_flag: "--zero-trust-attestation"
trigger_env: CLOUD_EVIDENCE_ZERO_TRUST_ATTESTATION
depends_on: [B.B1, E.E1, E.E2, J.J3, J.J3b, L.L1, L.L2, O.O5, P.P1]
blocks: [Q.Q1, Q.Q2]
estimated_effort: extra-large (8-12 person-weeks across 7 slices)
last_updated: 2026-06-07
---

# LOOP-X — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.
> Severity: high = ship-blocking; med = should fix in-loop; low = file
> as follow-up.

> Authoritative companion to `docs/loops/LOOP-X-SPEC.md` and the
> per-slice docs at `docs/slices/X/X.X[1-7].md`. Read those for context
> before acting on any risk here.

> **UNIVERSAL APPLICABILITY**: LOOP-X applies to **every** CSP whose
> authorization package will be evaluated under FedRAMP 20x. OMB M-22-09
> (Federal Zero Trust Strategy, Jan 26 2022) is binding on every Federal
> civilian Executive Branch agency; agency customers flow the strategy
> down to their CSPs through Acceptable Risk Safeguards and through
> FedRAMP 20x Key Security Indicators that incorporate ZTA expectations.
> The `--zero-trust-attestation` flag is a CI-friendly knob for
> development; the production orchestrator emits X.X1..X.X7 in every
> FedRAMP 20x submission build. There is no opt-out at the regulation
> level. Every risk below activates unconditionally for any CSP holding
> even one Federal contract that touches a civilian-agency customer or
> a DoD customer who has elected to apply DoD Zero Trust Reference
> Architecture v2.0 (Sep 2022).

> Last updated: 2026-06-07.

> Companion reading (cross-reference these registers when triaging a
> LOOP-X risk that interacts with another loop):
>
> - `LOOP-E-RISKS.md` — ConMon delta engine; LOOP-X depends on E.E1 +
>   E.E2 for the streaming telemetry that feeds the Visibility &
>   Analytics cross-cutting pillar evidence.
> - `LOOP-J-RISKS.md` — Supply chain + privileges; J.J3 + J.J3.b are the
>   prerequisite SLSA build attestations + cosign verifications that
>   the Application Workload pillar's runtime-verification evidence
>   reads.
> - `LOOP-L-RISKS.md` — Customer Responsibility Matrix; LOOP-X PDP/PEP
>   separation evidence references the CRM inheritance map (L.L1 +
>   L.L2) when the PDP is in the customer's authority boundary.
> - `LOOP-O-RISKS.md` — AI/ML governance; O.O5 model cards feed the
>   Data pillar's data-classification + provenance evidence.
> - `LOOP-P-RISKS.md` — Insider threat + workforce security; the
>   Identity pillar's continuous-authentication evidence (per ZTMM v2.0
>   Identity pillar "Optimal" stage) leans on P.P1's anomaly-detection
>   signals.
> - `LOOP-B-RISKS.md` — POA&M emitter; LOOP-X uses POA&M cascade for
>   pillar-stage gap remediation tracking (any pillar at stage below
>   the agency-mandated target maturity emits a POA&M).
> - `LOOP-S-RISKS.md` — DFARS equivalency; DoD-prime CSPs that elect
>   the DoD ZTRA v2.0 overlay must reconcile civilian ZTMM v2.0 + DoD
>   ZTRA v2.0 evidence (X-X33 cross-overlay).

---

## Table of Contents

- [Cross-cutting risks (apply to ALL slices in LOOP-X)](#cross-cutting-risks-apply-to-all-slices-in-loop-x)
  - Pillar score inflation + maturity rubric drift (X-X1..X-X8)
  - PDP/PEP architecture (X-X9..X-X14)
  - Identity pillar (X-X15..X-X20)
  - Device pillar (X-X21..X-X25)
  - Network pillar (X-X26..X-X30)
  - Application Workload pillar (X-X31..X-X35)
  - Data pillar (X-X36..X-X40)
  - Visibility & Analytics cross-cutting (X-X41..X-X44)
  - Automation & Orchestration cross-cutting (X-X45..X-X48)
  - Governance cross-cutting + policy-as-code drift (X-X49..X-X53)
  - Cross-loop interaction + REO / submission ecosystem (X-X54..X-X60)
- [Per-slice risks](#per-slice-risks)
  - X.X1 — ZTMM v2.0 pillar catalogue extractor
  - X.X2 — Identity pillar evidence aggregator
  - X.X3 — Device pillar evidence aggregator
  - X.X4 — Network pillar microsegmentation prover
  - X.X5 — Application Workload pillar runtime-verification aggregator
  - X.X6 — Data pillar classification + provenance aggregator
  - X.X7 — Pillar-stage scorecard + signed attestation + .docx emitter
- [External dependencies that may change](#external-dependencies-that-may-change)
- [Resolved risks (historical)](#resolved-risks-historical)
- [Resume-from-fresh-session checklist](#resume-from-fresh-session-checklist)

---

## Cross-cutting risks (apply to ALL slices in LOOP-X)

### X-X1 — ZTMM v2.0 vs v1.0 pillar-rubric drift (Identity pillar reorganized)

- **Description**: CISA's Zero Trust Maturity Model published v1.0 on
  Aug 31 2021 and v2.0 on Apr 11 2023. The two versions differ
  materially: v2.0 introduces a 4-stage rubric (`Traditional`,
  `Initial`, `Advanced`, `Optimal`) replacing v1.0's 3-stage rubric
  (`Traditional`, `Advanced`, `Optimal`); v2.0 splits the Identity
  pillar's "Authentication" function into "Authentication" +
  "Identity Stores" + "Risk Assessments"; v2.0 introduces a separate
  `Governance` cross-cutting capability previously folded into
  Visibility & Analytics. A CSP whose LOOP-X catalogue is pinned to
  v1.0 ships a scorecard that the agency CIO will reject as
  out-of-date; the inverse — a v2.0 catalogue evaluated against a
  v1.0-trained 3PAO checklist — produces apparent maturity gaps that
  are merely rubric-version mismatches. CISA has signalled minor
  errata work on v2.0 + a horizon v3.0 (no published date as of
  2026-06-07).
- **Severity**: high (correctness signal; agency rejection risk).
- **Mitigation**: X.X1's `core/ztmm-catalog.ts` carries a
  `catalog_version = "ZTMM-v2.0-2023-04-11"` constant + `revision_pin
  = "errata-2024-02"` field; X.X7's scorecard renderer emits the
  version + revision in the signed envelope header + on the .docx
  cover page. Extractor (`scripts/extract-ztmm-catalog.mjs`) asserts
  the source PDF's SHA-256 against pinned hashes; mismatch flags
  `REQUIRES-OPERATOR-INPUT: confirm-against-new-revision`. The
  catalog data file (`data/ztmm-v2.0.json`) records each pillar's
  source page reference for forensic correlation. Operator override
  via `zero-trust-config.yaml ztmm_version_override` for early
  adopters of a future v3.0. CHANGELOG entry per catalogue refresh.
- **Status**: open.

### X-X2 — Pillar score inflation (operator/dev incentive to over-claim)

- **Description**: The pillar scorecard surfaces a per-pillar maturity
  stage (`Traditional` / `Initial` / `Advanced` / `Optimal`). The
  difference between `Advanced` and `Optimal` is procurement-visible
  in agency Marketplace listings + downstream RFPs that condition
  award on minimum maturity. There is a real operator/developer
  incentive to over-claim. Adversarial pattern: a developer maps a
  partial-coverage capability (e.g. "MFA on 60% of accounts") to
  `Optimal` rather than `Initial` because the underlying boolean
  field reads "MFA enabled" without considering coverage. A 3PAO
  who audits the underlying evidence will downgrade — but a CSP
  whose first-cut scorecard is over-stated faces an embarrassing
  walk-back.
- **Severity**: high (false-attestation risk; cascading procurement
  + trust).
- **Mitigation**: X.X7's `core/ztmm-stage-classifier.ts` is
  deterministic and evidence-driven: every stage assignment carries
  `stage_rationale: text` + `supporting_evidence_ids: string[]` (list
  of LOOP-E/J/L/O/P artefact IDs) + `coverage_percentage: number`
  (denominator + numerator both recorded). Coverage below the stage's
  minimum threshold (Initial >= 25%, Advanced >= 75%, Optimal >= 95%)
  cannot be promoted. Per-pillar a "high-confidence" floor caps the
  reported stage at `Initial` until LOOP-E.E1 streaming evidence
  reaches the per-capability minimum (default 30 days of green
  telemetry). Adversarial test A1 in `LOOP-X-SPEC.md §7.3` pins a
  partial-coverage MFA case asserting it scores `Initial`, not
  `Advanced`. CHANGELOG entry per scorecard release lists the
  coverage thresholds.
- **Status**: open.

### X-X3 — Maturity rubric inversion (NIST SP 800-207A microsegmentation vs ZTMM Network pillar)

- **Description**: NIST SP 800-207A (Sep 2023, "A Zero Trust
  Architecture Model for Access Control in Cloud-Native Applications
  in Multi-Cloud Environments") emphasises microsegmentation at the
  service-mesh layer. CISA ZTMM v2.0's Network pillar tracks
  microsegmentation at the L3/L4 boundary + adds an
  application-aware-routing function. The two surfaces are not 1:1.
  A CSP whose evidence aggregator equates "service-mesh mTLS
  enabled" with "ZTMM Network pillar Advanced" will over-claim:
  ZTMM Advanced requires both L3/L4 segmentation AND
  application-aware routing AND continuous trust verification on
  east-west traffic. SP 800-207A's model is necessary but not
  sufficient.
- **Severity**: high (false-attestation; rubric mis-application).
- **Mitigation**: X.X4's `core/ztmm-network-aggregator.ts` joins
  three evidence streams: (a) L3/L4 segmentation evidence from
  LOOP-E.E2 cloud-config readers (AWS Security Groups, GCP firewall
  rules, Azure NSGs), (b) service-mesh mTLS evidence from LOOP-J's
  cluster-scrape (Istio AuthorizationPolicy, Linkerd ServerPolicy,
  AWS App Mesh VirtualRouter), (c) application-aware routing
  evidence from operator-supplied service-mesh policy commits
  (signed via cosign). A pillar stage is computed only when all
  three streams are present + green for the configured window
  (default 30 days). Per-stream coverage carries
  `coverage:stream-<stream-id>` markers in
  `out/inventory-coverage.json`. Cross-reference SP 800-207A §3.2.1
  "Service-to-service microsegmentation" verbatim in the runbook.
  Adversarial test A4 pins an mTLS-only + no-segmentation case
  asserting Network pillar scores `Initial`, not `Advanced`.
- **Status**: open.

### X-X4 — OMB M-22-09 specific-target drift (24-month + FY24 deadlines)

- **Description**: OMB M-22-09 sets specific targets such as
  "Agencies must achieve specific zero trust security goals by the
  end of Fiscal Year (FY) 2024" + "Within 24 months" obligations
  scoped from Jan 26 2022 (i.e. Jan 26 2024). Agency customers
  reading a CSP's LOOP-X attestation expect the CSP to demonstrate
  evidence that aligns with M-22-09's explicit goals (e.g. "Agency
  staff use enterprise-managed identities to access the applications
  they use in their work. Phishing-resistant MFA protects those
  personnel from sophisticated online attacks."). A LOOP-X attestation
  that uses only ZTMM v2.0 capability labels without mapping back to
  M-22-09's specific goal numbers (G1–G35 organised by pillar) leaves
  agency CIOs without the cross-reference they need to clear the CSP.
- **Severity**: high (procurement signal; agency clearance dependency).
- **Mitigation**: `core/ztmm-omb-m22-09-crosswalk.ts` maps every ZTMM
  v2.0 capability to the corresponding M-22-09 paragraph + goal
  identifier (the crosswalk is opinionated; cf. X-X7-equivalent for
  T.T1). The signed attestation envelope carries a
  `omb_m22_09_alignment_summary` block enumerating each M-22-09 goal +
  the LOOP-X capabilities that contribute + the operator-attested
  stage; the .docx ships an "OMB M-22-09 Alignment" appendix table.
  The crosswalk records `mapping_source` (`omb-m22-09-appendix`,
  `cisa-ztmm-v2-0-appendix-b`, `operator-defined`) +
  `mapping_confidence` per row; low-confidence + unreviewed mappings
  refuse to contribute to a stage promotion. Cross-references
  GAO-23-105424 (May 2023) which audited M-22-09 progress.
- **Status**: open.

### X-X5 — DoD ZTRA v2.0 overlay conflict (DoD-prime CSPs)

- **Description**: DoD's Zero Trust Reference Architecture v2.0 (Sep
  2022; updated through DoD ZT Strategy 21 Oct 2022 and DoD ZT
  Capabilities + Activities matrix Nov 2022) is structurally
  different from CISA ZTMM v2.0: DoD uses 7 pillars (User, Device,
  Application & Workload, Data, Network & Environment, Automation &
  Orchestration, Visibility & Analytics) with 152 Activities mapped
  to 45 Capabilities; CISA uses 5 pillars + 3 cross-cutting
  capabilities + a 4-stage rubric. A DoD-prime CSP needs BOTH
  surfaces; treating them as interchangeable produces evidence that
  satisfies neither audience.
- **Severity**: high for DoD-prime CSPs; low otherwise (cross-loop
  with LOOP-S).
- **Mitigation**: `core/ztmm-dod-overlay.ts` is conditional on
  `zero-trust-config.yaml dod_overlay: true`; when set, the
  pipeline emits BOTH a `out/ztmm-civilian-v2.0-attestation.json`
  AND a `out/dod-ztra-v2.0-attestation.json` envelope sharing the
  same underlying evidence index but rendered against the two
  rubrics. The DoD overlay catalog (`data/dod-ztra-v2.0.json`)
  carries the 152 Activities + 45 Capabilities + the per-Activity
  pre-requisite Target-Year. CHANGELOG documents the dual-emit
  pattern. Cross-references LOOP-S.S3 DFARS equivalency letter
  (which can cite the DoD ZTRA attestation). Runbook documents how
  to coordinate with the DoD-customer's CIO on which rubric they
  consume for their Authorization to Operate review.
- **Status**: open.

### X-X6 — ZTMM "Initial" baseline below FedRAMP 20x KSI floor

- **Description**: ZTMM v2.0's `Initial` stage is the second of
  four (above `Traditional`). FedRAMP 20x KSIs already incorporate
  several capabilities at a level the ZTMM v2.0 rubric would
  characterise as `Advanced` (e.g. continuous MFA, automated
  vulnerability scanning, log streaming). A CSP whose scorecard
  reports `Initial` on a pillar because of a single sub-capability
  gap could mislead reviewers into thinking the CSP is overall
  below FedRAMP 20x KSI compliance — when in fact the CSP satisfies
  every KSI but missed one ZTMM sub-capability.
- **Severity**: med (reporting clarity).
- **Mitigation**: X.X7's scorecard renderer adds a per-pillar
  "FedRAMP 20x KSI floor" annotation; when the ZTMM stage is below
  the KSI floor for the pillar, the .docx + signed JSON surface
  "Pillar stage rubric does NOT imply non-compliance with FedRAMP
  20x KSIs; see KSI satisfaction matrix at out/ksi-satisfaction.json"
  callout. The signed envelope carries `ztmm_vs_ksi_alignment` block
  cross-referencing each pillar to the satisfied KSIs. Runbook
  documents the rubric distinction explicitly.
- **Status**: open.

### X-X7 — ZTMM pillar score is point-in-time, not continuous

- **Description**: A pillar stage assigned at attestation time
  reflects evidence available at that moment. Real Zero Trust
  posture decays: an Identity pillar at `Optimal` last month can
  drop to `Advanced` this month if a phishing-resistant MFA roll-out
  regressed for a sub-population. A static attestation does not
  capture decay; a 3PAO reviewing a year-old attestation expects
  current posture.
- **Severity**: med.
- **Mitigation**: X.X7 emits the scorecard with `attestation_window
  = "rolling-30-days"` semantics: every reported stage reflects the
  trailing 30-day median of the supporting LOOP-E.E1 streaming
  telemetry. The attestation has `valid_until: ISO8601` set to
  `signed_at + 30 days`; LOOP-Q.Q1 Marketplace badge consumer
  refuses to render a "Zero Trust Compliant" badge from an envelope
  past `valid_until`. Runbook documents the renewal cadence (T-7,
  T-3, T-1 day warnings) + the requires-operator-input diagnostic.
- **Status**: open.

### X-X8 — Pillar maturity self-attestation is not a substitute for control assessment

- **Description**: A LOOP-X scorecard is a self-attestation of ZTMM
  v2.0 pillar maturity; it is NOT an assessor-validated control
  assessment. A reader who treats the scorecard as equivalent to a
  3PAO Security Assessment Report finding will draw incorrect
  conclusions. M-22-09 explicitly contemplates agency CIOs +
  inspectors-general + GAO consuming the attestation as a planning
  input, not as an authorization decision.
- **Severity**: high (legal/operational distinction; reader
  misinterpretation cascades).
- **Mitigation**: Every LOOP-X emit (signed JSON envelope + .docx +
  Marketplace badge JSON) carries an explicit disclaimer block
  citing M-22-09's purpose statement verbatim. The .docx cover page
  reads "This is a self-attestation under OMB M-22-09; it is not a
  3PAO control assessment under NIST SP 800-53A and does not
  substitute for the FedRAMP 20x Security Assessment Report." The
  signed envelope `disclaimer` field is required by JSON schema +
  asserted in unit tests. Cross-loop with LOOP-F (3PAO assessor
  artefacts) — LOOP-F renderers explicitly cite LOOP-X as a
  *complementary* artefact, not a substitute.
- **Status**: open.

### X-X9 — PDP-PEP separation collapse (single component performs both)

- **Description**: NIST SP 800-207 §3.1 mandates logical separation
  between the Policy Decision Point (PDP) and the Policy Enforcement
  Point (PEP). A CSP that runs an AWS IAM-only identity model with
  no separate decision engine is collapsing PDP into PEP: the IAM
  policy engine both decides + enforces. SP 800-207 explicitly warns
  that collapsed-architecture deployments are at risk of failing
  ZTA self-assessment because changing the decision policy requires
  re-deploying the enforcement plane, which violates the "dynamic"
  property in §2 Tenet 5. A CSP attesting "PDP-PEP separated" on the
  scorecard without an actual decision-engine layer (OPA / Cedar /
  custom PDP service) is over-claiming.
- **Severity**: high (architectural ZTA correctness).
- **Mitigation**: X.X7's `core/pdp-pep-separation-prover.ts`
  requires evidence of (a) at least one PDP service distinct from
  the underlying compute resource (sample: Open Policy Agent
  deployment, AWS Verified Permissions service, Azure Authorization
  Policy Service, Cedar policy engine), AND (b) PEPs that consult
  the PDP via API / sidecar / admission controller pattern, AND (c)
  policy change events that took effect WITHOUT re-deploying the
  PEP (sampled from the trailing 30-day audit log). Absent any of
  the three, the Network pillar's Policy Enforcement function is
  capped at `Initial`. Adversarial test A5 pins the IAM-only
  collapsed-architecture case. Cross-references SP 800-207 §3.1
  + §3.1.1 verbatim in the runbook.
- **Status**: open.

### X-X10 — PDP-PEP separation false-pass (sidecar without policy independence)

- **Description**: A sidecar pattern (Envoy + OPA, Istio +
  ext_authz, Linkerd + service-policy) appears to satisfy PDP-PEP
  separation but can be false-pass if the OPA policy bundle is
  hard-coded into the PEP's container image (i.e. the policy is
  not actually dynamically loaded). A 3PAO reviewing pipeline
  config could discover that policy updates require image rebuilds
  — collapsing the separation back to PEP-only.
- **Severity**: high (architectural false-pass).
- **Mitigation**: X.X7's PDP/PEP prover additionally asserts the
  PDP fetches policy from a dedicated policy store (S3 bucket,
  configmap, OPA bundle server, AWS Verified Permissions store)
  AND that the policy store's `last_modified_at` audit log shows
  at least one policy update in the trailing 30 days that took
  effect WITHOUT a PEP redeployment. Cross-references the
  `core/policy-store-audit.ts` reader. Adversarial test A6 pins
  the hard-coded-policy-bundle case asserting `Initial` rather
  than `Advanced`.
- **Status**: open.

### X-X11 — PDP availability + integrity (PDP outage degrades enforcement)

- **Description**: A separated PDP introduces a runtime dependency:
  if the PDP is unavailable, the PEP must either fail-closed
  (deny by default — Tenet 1) or fail-open (allow by default —
  violates ZTA). A CSP that runs fail-open as a graceful-degradation
  pattern is technically a PDP/PEP separation but is operationally
  violating Tenet 1. The reverse risk: fail-closed PDP outage takes
  down the entire production environment.
- **Severity**: high (Tenet 1 correctness; operational risk).
- **Mitigation**: X.X7 surfaces `pdp_failure_mode` per PDP/PEP
  pairing — one of `fail-closed-deny`, `fail-closed-cached`,
  `fail-open`. The `fail-open` value caps the Policy Enforcement
  function at `Traditional`. Cross-references LOOP-E.E1 streaming
  telemetry for PDP availability SLO + LOOP-G.G2 incident reports
  for PDP-outage events. Adversarial test A7 pins the fail-open
  case. Runbook documents the cached-decision TTL pattern (PDP
  decisions cached at PEP for a bounded window — typically 60-300s
  — as a defence-in-depth between Tenet 1 and operational
  availability).
- **Status**: open.

### X-X12 — PEP coverage gap (off-network / off-managed devices bypass PEP)

- **Description**: A PEP only enforces traffic that passes through
  it. Off-network developer laptops, BYOD endpoints, third-party
  SaaS integrations that route around the PEP, and out-of-band
  emergency access procedures all bypass the PEP. A pillar stage
  computed from PEP enforcement records will be over-stated if it
  does not also track the per-device coverage rate.
- **Severity**: high (coverage gap masks under-enforcement).
- **Mitigation**: X.X7 joins the PEP enforcement log against the
  device pillar's managed-device registry (X.X3) + the identity
  pillar's authenticated-session registry (X.X2). A device or
  session that authenticated but did NOT route through a PEP is
  recorded as `pep_coverage_miss` + counted toward the
  Initial/Advanced/Optimal coverage denominator. Coverage below
  95% caps the Network pillar at `Advanced` (not `Optimal`); below
  75% caps at `Initial`. Adversarial test A8 pins the BYOD-bypass
  case. Cross-references LOOP-P.P1 insider-threat monitoring for
  out-of-band-access detection.
- **Status**: open.

### X-X13 — PDP policy-as-code drift (policy in repo vs policy in production)

- **Description**: A mature PDP setup stores policy as code in a
  git repository, signs the policy bundle, and deploys it to the
  PDP. Drift between the source-of-truth repo and the production
  PDP — e.g. an emergency hot-patch applied via PDP console without
  a commit, or a deployment that lagged a commit — invalidates the
  Governance cross-cutting capability's "policy-as-code" claim.
- **Severity**: high (cross-cutting governance signal).
- **Mitigation**: X.X7 reads (a) the policy repo HEAD commit hash
  + signed bundle SHA-256, (b) the PDP-resident policy SHA-256
  (queried via PDP admin API), (c) the deployment audit log. A
  mismatch between (a) + (b) + (c) triggers `policy_drift_detected`
  emit + caps the Governance capability at `Initial`. Cross-loop
  with LOOP-J.J3.b — the policy-bundle cosign signature is verified
  via the same cosign+Rekor chain. Runbook documents the
  re-synchronisation procedure. CHANGELOG entry per drift detected.
- **Status**: open.

### X-X14 — PDP audit-log integrity (PDP decision log is the ZTA evidence base)

- **Description**: Every PDP decision is the atomic evidence unit
  for ZTA. If the PDP audit log is not append-only, signed, or
  tamper-evident, an attacker (or insider) who alters a decision
  log entry can hide an enforcement bypass. SP 800-207 §3.3
  requires "Continuous monitoring" + §2 Tenet 7 requires "as much
  information as possible about the current state of assets" — both
  presume an integrity-protected audit log.
- **Severity**: high (evidence-base integrity).
- **Mitigation**: X.X7's prover requires PDP audit logs to be (a)
  streamed to an append-only sink (AWS CloudTrail with S3 Object
  Lock, GCP Cloud Audit Logs with retention policy, Azure Monitor
  with immutable retention) AND (b) hash-chained per LOOP-H.H1
  long-term storage classifier AND (c) signed by a tracker-resident
  Ed25519 key on ingest. Per-event records carry
  `audit_log_sink_id` + `hash_chain_root` + `signing_key_id` fields.
  Cross-references LOOP-H.H1 + LOOP-E.E2 for the long-term storage
  + streaming patterns. Adversarial test A9 pins a tampered-log case
  asserting Visibility & Analytics caps at `Traditional`.
- **Status**: open.

### X-X15 — Identity pillar single-IdP risk (single point of compromise)

- **Description**: An Identity pillar at `Optimal` requires
  phishing-resistant MFA, continuous authentication signals, and
  identity-store consolidation. A common CSP pattern is to
  consolidate to a single SaaS IdP (Okta, Azure AD / Entra ID,
  Google Workspace, AWS Identity Center). Consolidation is good
  for ZTA discipline but introduces a single point of catastrophic
  compromise. A breached IdP (Okta 2022 incident, Microsoft DKIM
  2023 incident) collapses every downstream PEP's trust basis. A
  scorecard that reports `Optimal` on Identity without recording
  the IdP concentration risk gives a misleading picture.
- **Severity**: med (operational/architectural; cross-cutting risk).
- **Mitigation**: X.X2's Identity pillar emit includes
  `identity_provider_inventory: { idp_id, idp_kind, user_count,
  is_primary }` array; when `idp_count_authenticated_within_30d <
  2` AND `is_primary[0].user_count > 0.8 * total_users`, an
  `identity_concentration_risk: high` flag is surfaced in the
  attestation envelope + .docx. The pillar stage is not
  automatically capped (concentration is operationally acceptable
  if the IdP itself has compensating controls), but the flag is
  surfaced for 3PAO + agency-CIO visibility. Runbook documents
  the IdP-failover pattern + the per-IdP break-glass account
  requirement.
- **Status**: open.

### X-X16 — Identity pillar phishing-resistant MFA coverage gap (M-22-09 Goal G3)

- **Description**: OMB M-22-09 explicitly requires "Phishing-
  resistant MFA" for all agency staff. CISA ZTMM v2.0 Identity
  pillar's Authentication function similarly progresses from
  "passwords + memorized secrets" at Traditional to "phishing-
  resistant MFA" at Advanced/Optimal. A CSP attesting `Optimal` on
  Identity with phishing-resistant MFA enabled for, say, 70% of
  privileged accounts and 40% of standard accounts is over-claiming;
  M-22-09 Goal G3 reads "across the agency, no exceptions" except
  for a narrow break-glass set.
- **Severity**: high (M-22-09 explicit goal; over-claim risk).
- **Mitigation**: X.X2's MFA coverage join reads (a) per-user MFA
  method registration from each IdP API, (b) per-session MFA
  method actually used from the trailing 30-day session log, (c)
  the inventory of break-glass accounts (operator-supplied via
  `zero-trust-config.yaml break_glass_accounts[]`). The pillar
  stage assignment requires `phishing_resistant_mfa_coverage >=
  95%` for `Advanced` and `>= 99%` for `Optimal` (excluding
  break-glass which has a separate hard-cap of <= 10 accounts).
  Methods recognised as phishing-resistant: WebAuthn / FIDO2,
  PIV/CAC, smart-card, hardware token (YubiKey). Methods NOT
  recognised: SMS OTP, push notification without number-matching,
  voice OTP, app-based TOTP. The recognised-method list is in
  `data/phishing-resistant-mfa-methods.json` (auditable). Cross-
  references CISA "Implementing Phishing-Resistant MFA" guide
  (Oct 31 2022). Adversarial test A10 pins a 70%-coverage case
  asserting `Initial`.
- **Status**: open.

### X-X17 — Identity pillar service-account / non-person-entity coverage

- **Description**: M-22-09 Goal G2 + ZTMM Identity pillar capture
  human identities, but production environments are dominated by
  non-person entities (NPEs) — service accounts, machine
  identities, CI/CD tokens, API keys. A CSP that reports `Optimal`
  Identity for human users while running long-lived static API
  keys for service-to-service is failing Tenet 6 ("All
  authentication and authorization are dynamic and strictly
  enforced before access is allowed"). NIST SP 800-207A §3.1
  explicitly extends ZTA to service identities.
- **Severity**: high (ZTA Tenet 6; common false-pass pattern).
- **Mitigation**: X.X2's Identity pillar emit includes
  `npe_identity_inventory` separate from human identities + the
  `npe_workload_identity_mechanism` per NPE — one of
  `oidc-federated-short-lived` (e.g. AWS IRSA / IAM Roles for
  Service Accounts, GCP Workload Identity, Azure Managed Identity),
  `spiffe-svid` (SPIFFE/SPIRE), `cosign-keyless-via-oidc`, or
  `static-long-lived` (capped at `Traditional` for the NPE subset).
  Pillar stage for NPE subset is computed independently of human
  identity stage; the scorecard surfaces both. Adversarial test A11
  pins a hybrid case (human Optimal + NPE Traditional) asserting
  overall Identity pillar = `Initial` (worst-of). Cross-references
  SP 800-207A §3.1 verbatim. Runbook documents the per-cloud
  workload identity pattern.
- **Status**: open.

### X-X18 — Identity pillar continuous authentication false-pass

- **Description**: ZTMM v2.0 Identity pillar's Risk Assessments
  function at `Optimal` requires "Continuous, risk-based
  authentication using real-time analytics". A CSP enabling Okta
  Adaptive MFA or Azure Conditional Access with risk-based policies
  is a step in this direction, but if the risk signals are coarse
  (geo-IP-only) or the policies trigger only at session-start
  rather than continuously, the implementation falls short of
  Optimal. Operators commonly mark this `Optimal` because the
  feature is "on".
- **Severity**: med (rubric-application correctness).
- **Mitigation**: X.X2's continuous-authentication evidence
  requires (a) at least 3 distinct risk signals (geo-IP +
  device-posture + behavioral + threat-intel + impossible-travel
  + token-binding) AND (b) at least one mid-session re-evaluation
  per session (sampled from the trailing 30-day session log) AND
  (c) policy enforcement at the PEP for at least 50% of detected
  high-risk sessions. Coverage thresholds promote the function.
  Cross-references LOOP-P.P1 insider-threat behavioral signals.
  Adversarial test A12 pins a geo-IP-only case asserting `Initial`.
- **Status**: open.

### X-X19 — Identity pillar privileged access management gap (PAM)

- **Description**: Privileged Access Management — just-in-time
  elevation, session recording, vaulted credentials — is a
  recurring Identity pillar Advanced/Optimal requirement.
  CSPs commonly rely on AWS IAM roles + SSM Session Manager and
  call it "PAM done". The gap: session recording is often not
  enabled by default; just-in-time elevation often requires manual
  ticket workflow rather than approval-on-policy; vaulted
  credentials may not be rotated short-lived.
- **Severity**: high (privileged access is the highest-value
  attack target).
- **Mitigation**: X.X2's PAM evidence requires (a) just-in-time
  elevation via an approval workflow (ticketing + policy
  evaluation) for every privileged session, AND (b) session
  recording enabled for >= 95% of privileged sessions, AND (c)
  credential rotation interval <= 24 hours for any static
  privileged credential. Stage promotion requires all three.
  Cross-references LOOP-P.P1 privileged-user monitoring.
  Adversarial test pins a SSM-only case asserting `Initial`.
- **Status**: open.

### X-X20 — Identity store consolidation vs federation (M-22-09 Goal G1)

- **Description**: M-22-09 Goal G1 requires "Agency staff use
  enterprise-managed identities". ZTMM v2.0 Identity Stores
  function at Advanced/Optimal requires consolidated identity
  stores. A CSP with multiple identity stores federated via SAML/
  OIDC is technically meeting the consolidation intent but a
  fragmented federation pattern (5+ identity stores) creates
  audit-trail gaps + makes deprovisioning lag. The cleanest
  pattern is single primary store + tightly bounded federation.
- **Severity**: med.
- **Mitigation**: X.X2's identity-store inventory surfaces
  `identity_store_count` + `identity_store_federation_topology`
  (one of `single-primary`, `hub-and-spoke`, `peer-to-peer`,
  `mesh`); pillar stage promotion requires `single-primary` or
  `hub-and-spoke` with documented federation contracts. Coverage
  threshold: <= 3 identity stores for `Advanced`, <= 2 for
  `Optimal`. Operator overrides via `zero-trust-config.yaml
  identity_store_overrides{}` for legitimate multi-store cases
  (e.g. customer-facing vs employee-facing separation). Cross-
  references the M-22-09 verbatim text in the runbook.
- **Status**: open.

### X-X21 — Device pillar BYOD coverage gap

- **Description**: ZTMM v2.0 Device pillar requires "Compliance
  Enforcement" + "Asset & Supply Chain Risk Management" + "Resource
  Access" at Advanced/Optimal stages. A CSP with a strong managed-
  device program (MDM, EDR, attestation) often still has a BYOD
  population (contractors, mobile-only roles, third-party
  consultants) that bypasses the program. M-22-09 Goal G6 expects
  "device inventory of every device authorized for government use",
  with the implication that BYOD must be controlled or excluded —
  not silently allowed.
- **Severity**: high (M-22-09 explicit goal; coverage gap masks
  under-enforcement).
- **Mitigation**: X.X3's Device pillar evidence aggregator reads
  (a) MDM-managed device count from Jamf / Intune / Workspace ONE
  / Google MDM APIs, (b) authenticated-session device fingerprints
  from the IdP session log (cross-join against X.X2), (c)
  operator-attested BYOD program details from
  `zero-trust-config.yaml byod_policy{}`. The pillar stage is
  computed using `managed_device_coverage = managed_sessions /
  total_authenticated_sessions`; coverage below 95% caps at
  `Advanced`; below 75% caps at `Initial`. BYOD sessions that do
  not satisfy the BYOD-policy gates (e.g. require Conditional
  Access + reduced privileges + ephemeral container) are recorded
  as `unmanaged_session_with_policy_gap`. Adversarial test A13
  pins a contractor-laptop case. Cross-references CISA's BYOD
  guidance (Apr 2023) verbatim in runbook.
- **Status**: open.

### X-X22 — Device pillar attestation chain (TPM / DICE / measured boot)

- **Description**: ZTMM v2.0 Device pillar's "Device Threat
  Protection" + "Asset & Supply Chain Risk Management" at Optimal
  require device-level attestation — TPM-backed key store, DICE
  identity, measured boot, runtime-integrity. A CSP attesting
  Device `Optimal` without an attestation chain is over-claiming.
  Conversely, requiring TPM attestation on every device is often
  impractical for older fleet.
- **Severity**: med.
- **Mitigation**: X.X3's attestation-chain evidence requires (a)
  TPM 2.0 or equivalent (Apple Secure Enclave, Google Titan) on
  >= 95% of managed devices, AND (b) measured-boot logs ingested
  into telemetry for >= 90% of devices, AND (c) device-attestation
  signed-quote verified at session-start for >= 80% of sessions.
  Below thresholds, the Device Threat Protection function caps at
  `Advanced`. Cross-references NIST SP 800-155 (Boot Integrity
  Measurement) + TCG TPM 2.0 Library spec. Adversarial test pins
  a no-attestation case.
- **Status**: open.

### X-X23 — Device pillar EDR coverage + telemetry quality

- **Description**: EDR is the Device pillar's runtime-detection
  staple. Coverage gaps (servers without EDR agent installed,
  EDR-stub-installed-but-not-reporting) are common. ZTMM v2.0
  Device pillar requires EDR coverage with real-time telemetry
  feeding the Visibility & Analytics cross-cutting capability.
- **Severity**: high.
- **Mitigation**: X.X3's EDR coverage join reads (a) EDR-installed
  device count from CrowdStrike / SentinelOne / Microsoft Defender
  / Carbon Black / similar EDR API, (b) device count from the
  managed-device registry. Coverage = installed / managed;
  threshold for `Advanced` = 95%; for `Optimal` = 99%. EDR
  telemetry freshness join: any EDR agent with no telemetry in 24
  hours is recorded as `edr_stale` + counted against coverage.
  Cross-references LOOP-E.E1 streaming telemetry pipeline.
- **Status**: open.

### X-X24 — Device pillar mobile device parity (iOS / Android management)

- **Description**: Mobile-device coverage gaps are a perennial ZTA
  failure mode. Server + workstation coverage is often strong but
  mobile MDM lags. A pillar stage that ignores mobile under-states
  posture; the inverse — counting unmanaged mobile devices toward
  coverage — over-states.
- **Severity**: med.
- **Mitigation**: X.X3's coverage denominator includes ALL
  authenticated devices regardless of form factor; mobile devices
  without MDM enrolment are counted as `unmanaged`. Operator
  override for legitimate exclusions (e.g. agency-furnished
  mobile-only devices that authenticate via a separate identity
  bridge) via `zero-trust-config.yaml mobile_device_overrides{}`.
- **Status**: open.

### X-X25 — Device pillar firmware + supply-chain integrity

- **Description**: ZTMM v2.0 Device pillar "Asset & Supply Chain
  Risk Management" at Advanced/Optimal expects firmware integrity
  monitoring + hardware bill of materials (HBOM). Most CSPs do
  not have HBOM today; firmware monitoring is partial. Over-claim
  risk.
- **Severity**: med.
- **Mitigation**: Pillar function caps at `Initial` until HBOM
  evidence (CycloneDX HBOM or operator-attested) exists for >= 50%
  of fleet AND firmware-integrity telemetry exists for >= 50% of
  fleet. Cross-references CISA HBOM guidance (2024). Runbook
  documents the HBOM adoption roadmap.
- **Status**: open.

### X-X26 — Network pillar microsegmentation false-pass (over-broad allow rules)

- **Description**: A CSP may show that segmentation rules EXIST
  (Security Groups, VPC firewall rules, K8s NetworkPolicies) but
  the actual policy is over-broad (e.g. `0.0.0.0/0` allow on a
  database port). A naive aggregator that counts "policies exist"
  without analysing the allow scope will false-pass the
  microsegmentation evidence.
- **Severity**: high (false-pass; common pattern).
- **Mitigation**: X.X4's microsegmentation analyser computes per-
  rule "blast radius" — the number of distinct source IPs (or
  source service identities, for service-mesh policies) that the
  rule would admit. Allow rules with blast-radius > 1024 distinct
  source IPs or `0.0.0.0/0` source are flagged as `over-broad-allow`
  + counted toward `Initial` ceiling unless operator justifies via
  `zero-trust-config.yaml allowed_over_broad_rules[]` (e.g. public
  HTTPS endpoint). Adversarial test A14 pins an over-broad-allow
  case asserting Network pillar Network Segmentation function
  scores `Initial`. Cross-references NIST SP 800-207A §3.2.1
  verbatim.
- **Status**: open.

### X-X27 — Network pillar east-west traffic encryption gap

- **Description**: ZTMM v2.0 Network pillar Traffic Management at
  Advanced/Optimal requires encryption of east-west traffic (not
  just north-south). A CSP with TLS-terminated load-balancer + HTTP
  backend is failing east-west encryption. Service-mesh mTLS is the
  canonical answer but adoption is uneven.
- **Severity**: high.
- **Mitigation**: X.X4 reads service-mesh mTLS coverage from Istio
  / Linkerd / AWS App Mesh control planes; coverage = mTLS-enforcing
  services / total services. Threshold for `Advanced` = 75% mTLS
  enforced; for `Optimal` = 95%. Workloads outside the mesh (legacy
  VMs, lambda functions, managed databases) require encryption
  evidence from the cloud SDK (RDS in-transit encryption, S3
  endpoint TLS, etc.). Operator-attested exclusions via
  `zero-trust-config.yaml east_west_exclusions[]` for legitimate
  cases (debug-only loopback, ephemeral test environment).
- **Status**: open.

### X-X28 — Network pillar resilience + DNS encryption

- **Description**: ZTMM v2.0 Network pillar Resilience function +
  M-22-09 Goal G14 require encrypted DNS. A CSP using AWS
  Route53 default DNS without DoH/DoT or running internal DNS
  unencrypted is failing the goal.
- **Severity**: med.
- **Mitigation**: X.X4 reads DNS configuration from each cloud's
  DNS service; verifies DoH/DoT enabled for resolvers + DNSSEC
  enabled for zones. Threshold for `Advanced` = DoH/DoT enforced
  + DNSSEC on >= 75% of zones; for `Optimal` = DNSSEC on >= 95% of
  zones. Cross-references M-22-09 Goal G14 verbatim. Runbook
  documents AWS Route53 DoH/DoT configuration steps.
- **Status**: open.

### X-X29 — Network pillar SD-perimeter / service-mesh sprawl

- **Description**: A mature ZTA Network pillar typically uses 1-2
  service mesh implementations + a unified SD-perimeter overlay
  (Tailscale / Cloudflare Zero Trust / Zscaler / Palo Alto Prisma
  / Cisco Duo Beyond). Mesh sprawl (e.g. 3 different meshes across
  4 cloud accounts) creates policy gaps + interop complexity. The
  scorecard over-states posture if it does not capture the sprawl.
- **Severity**: med.
- **Mitigation**: X.X4 enumerates distinct service-mesh + SD-
  perimeter implementations + counts coverage per implementation;
  surfaces `mesh_sprawl_index` (number of distinct meshes per
  account-pair). High sprawl index (> 3 meshes) flags Network
  pillar as `Initial`-capped on the Network Segmentation function.
  Operator override via `zero-trust-config.yaml acceptable_mesh_
  sprawl: true` for legitimate multi-mesh patterns (e.g. agency
  customer requires a specific mesh).
- **Status**: open.

### X-X30 — Network pillar legacy compatibility (TLS 1.0/1.1, plaintext protocols)

- **Description**: ZTMM v2.0 Traffic Management at Advanced/Optimal
  prohibits legacy crypto. A CSP with even a small population of
  TLS 1.0/1.1 endpoints or plaintext SMTP/FTP/Telnet is failing
  ZTA Tenet 4 ("Access to individual enterprise resources is
  granted on a per-session basis").
- **Severity**: high (Tenet 4; common gap).
- **Mitigation**: X.X4 scans cloud load-balancers + API gateways +
  service endpoints for minimum TLS version + cipher suite; flags
  TLS < 1.2 as `legacy_crypto_finding`. ZTMM Traffic Management
  caps at `Traditional` if any `legacy_crypto_finding` exists.
  Cross-references NIST SP 800-52 Rev 2. Cross-loop with LOOP-R
  PQC migration — PQC-readiness emerges from same evidence
  surface (TLS configuration audit).
- **Status**: open.

### X-X31 — Application Workload pillar cosign verification false-pass

- **Description**: ZTMM v2.0 Application Workload pillar's
  "Application Access" + "Application Threat Protections" require
  workload provenance — every running container/lambda/VM image
  is signed + verified at admission. LOOP-J.J3.b ships the cosign
  verification chain. A CSP that runs admission control but in
  permissive-mode (audit-not-enforce) is false-passing the
  verification.
- **Severity**: high (LOOP-J cross-loop; false-pass pattern).
- **Mitigation**: X.X5 reads LOOP-J.J3.b's cosign verification log
  + the admission-controller configuration (K8s Kyverno / OPA
  Gatekeeper / Sigstore Policy Controller / AWS Sigstore /
  in-toto). Verification false-pass detection: if admission policy
  is `audit` rather than `enforce`, the function caps at
  `Initial`. If verification logs show any unsigned image admitted
  in the trailing 30 days outside the operator-attested exclusion
  list, the function caps at `Initial`. Adversarial test A15 pins
  a permissive-mode case. Cross-references LOOP-J.J3.b verbatim.
- **Status**: open.

### X-X32 — Application Workload pillar runtime-protection coverage

- **Description**: ZTMM v2.0 Application Workload pillar at
  Advanced/Optimal requires runtime workload protection — RASP /
  eBPF-based runtime monitoring (Falco / Tracee / Tetragon) /
  CNAPP. A CSP with only image-time scanning + no runtime layer is
  short of Advanced.
- **Severity**: med.
- **Mitigation**: X.X5 reads runtime-protection coverage from
  Falco DaemonSet inventory / CNAPP API / equivalent. Threshold
  for `Advanced` = 75% pod coverage; for `Optimal` = 95%.
  Cross-references LOOP-E.E1 streaming telemetry. Workloads
  outside Kubernetes (lambda, ECS Fargate) require equivalent
  evidence — AWS Lambda has Code Signing + Insights Lambda
  Extensions; Fargate has runtime security agents.
- **Status**: open.

### X-X33 — Application Workload pillar API gateway + WAF coverage

- **Description**: ZTMM v2.0 Application Workload pillar's
  "Application Access" function at Advanced/Optimal requires WAF
  + API gateway with per-request authentication + authorization
  + rate limiting. A CSP with AWS API Gateway but no WAF, or a WAF
  in count-mode rather than block-mode, is short.
- **Severity**: high.
- **Mitigation**: X.X5 reads WAF coverage from AWS WAFv2 / GCP
  Cloud Armor / Azure Front Door WAF / Cloudflare WAF. Coverage =
  WAF-protected endpoints / total internet-exposed endpoints.
  Threshold for `Advanced` = 75% block-mode; for `Optimal` = 95%
  block-mode. WAF in count-mode caps at `Initial`. Adversarial
  test pins a count-mode case.
- **Status**: open.

### X-X34 — Application Workload pillar AI/ML model serving (NIST AI RMF + M-24-10)

- **Description**: AI/ML models served as workloads have ZTA
  obligations beyond conventional containers: model provenance
  (LOOP-J.J3.b cosign on model artefacts), training-data
  provenance (LOOP-O.O5 model card), inference-time monitoring for
  drift + adversarial inputs (LOOP-O.O5 + LOOP-N). M-24-10 (OMB
  AI guidance, Mar 2024) adds further ZTA-adjacent requirements.
- **Severity**: med.
- **Mitigation**: X.X5 reads LOOP-O.O5 model-card index; for every
  in-scope AI model workload, requires (a) cosign-verified model
  artefact, (b) signed model card, (c) inference-monitoring
  telemetry. Cross-references LOOP-O-RISKS.md O-X*. Coverage
  threshold for the AI-model subset of the workload pillar matches
  the overall threshold but is computed separately. Runbook
  documents the LOOP-O integration.
- **Status**: open.

### X-X35 — Application Workload pillar secrets management (no plaintext secrets)

- **Description**: ZTMM v2.0 Application Workload pillar at
  Advanced/Optimal requires runtime secrets to be vaulted +
  ephemerally injected — no plaintext secrets in container images,
  no secrets in env vars at rest. Common false-pass: secrets
  manager exists but workloads still pull from env-var-baked
  config.
- **Severity**: high.
- **Mitigation**: X.X5 reads cluster-wide secrets-source
  inventory (AWS Secrets Manager / GCP Secret Manager / Azure
  Key Vault / HashiCorp Vault); cross-references workload manifests
  for inline-secret references. Inline secrets (literal credential
  strings in env vars / configmaps) flag the workload as
  `inline_secret_finding`. Stage caps at `Initial` if any
  `inline_secret_finding` in trailing 30 days. Cross-references
  LOOP-J.J3 provenance signing.
- **Status**: open.

### X-X36 — Data pillar classification drift (operator labels vs system labels)

- **Description**: ZTMM v2.0 Data pillar requires Data Categorization
  + Data Inventory Management + Data Encryption + Data Availability.
  The Categorization function at Advanced/Optimal expects automated
  classification (DLP, sensitive-data-discovery). A CSP relying on
  operator-applied labels alone is operator-driven; labels drift as
  data flows + transforms.
- **Severity**: high (Data pillar quality directly affects
  enforcement).
- **Mitigation**: X.X6 reads (a) cloud DLP findings from AWS Macie
  / GCP DLP / Azure Purview, (b) operator-supplied labels from
  resource tags (`fedramp_data_classification`), (c) data
  catalogue references (BigQuery / Glue / Purview). Drift
  detection: cloud DLP finding for a resource whose operator label
  is "public" or "internal" + DLP finding indicates PII/PHI/CUI →
  `classification_drift_finding`. Drift findings cap the
  Categorization function at `Initial`. Cross-references LOOP-M.M*
  privacy pipeline + LOOP-L.L1 CRM data-handling responsibility.
- **Status**: open.

### X-X37 — Data pillar encryption-at-rest + KMS key rotation

- **Description**: ZTMM v2.0 Data Encryption at Advanced/Optimal
  requires encryption-at-rest with customer-managed keys + rotation
  + automated key-policy enforcement. Common gap: encryption
  enabled with AWS-managed keys (vs CMK), or CMKs without
  rotation policy.
- **Severity**: high.
- **Mitigation**: X.X6 reads per-resource encryption configuration
  (S3 bucket, RDS instance, DynamoDB table, EBS volume, GCS bucket,
  Azure Storage). For each resource: (a) is encryption-at-rest
  enabled? (b) is the key customer-managed? (c) is rotation
  enabled? (d) is rotation interval <= 365 days? Threshold for
  `Advanced` = 95% CMK + rotation enabled; for `Optimal` = 99%.
  Cross-references LOOP-R PQC migration (PQC KEM emergence will
  obsolete current CMK algorithm choices over time).
- **Status**: open.

### X-X38 — Data pillar in-transit encryption (TLS / mTLS)

- **Description**: ZTMM v2.0 Data Encryption at Advanced/Optimal
  also requires in-transit encryption. Cross-cuts X-X27 (east-west
  network encryption) but adds data-store-specific requirements
  (e.g. RDS in-transit forced, S3 bucket TLS-only policy).
- **Severity**: high.
- **Mitigation**: X.X6 reads per-data-store TLS enforcement
  config; verifies policy enforces TLS for all reads + writes.
  Reuses the X-X27 service-mesh evidence for compute-to-compute
  traffic + adds compute-to-storage evidence.
- **Status**: open.

### X-X39 — Data pillar data loss prevention + egress monitoring

- **Description**: ZTMM v2.0 Data pillar Data Availability +
  Data Encryption functions overlap with DLP. M-22-09 Goal G27
  expects "an enterprise-wide logging and incident response
  capability". A CSP with no egress monitoring (CloudWatch Logs,
  VPC Flow Logs at the egress boundary, GCP VPC Service Controls)
  is failing.
- **Severity**: high.
- **Mitigation**: X.X6 reads VPC Flow Log coverage + egress-
  monitoring tooling inventory. Coverage = flow-logged subnets /
  total subnets. Threshold for `Advanced` = 95%. Cross-references
  LOOP-E.E2 streaming telemetry + LOOP-G.G2 incident reporting.
- **Status**: open.

### X-X40 — Data pillar data lifecycle + retention

- **Description**: ZTMM v2.0 Data pillar Data Inventory Management
  at Advanced/Optimal requires data lifecycle automation —
  retention policies, automated deletion at end-of-retention,
  data-subject-rights workflows. Common gap: retention policies
  exist on paper but lack automated enforcement.
- **Severity**: med.
- **Mitigation**: X.X6 reads S3 lifecycle policies, GCS lifecycle
  rules, Azure Storage lifecycle management; verifies retention
  enforcement for each in-scope bucket / dataset. Threshold for
  `Advanced` = lifecycle enforced on 75% of in-scope data; for
  `Optimal` = 95%. Cross-references LOOP-H.H1 long-term storage
  classifier.
- **Status**: open.

### X-X41 — Visibility & Analytics telemetry gap (logs collected but not analysed)

- **Description**: ZTMM v2.0 Visibility & Analytics cross-cutting
  capability at Advanced/Optimal requires not just log collection
  but real-time analytics. A CSP streaming logs to S3 + Splunk
  without active detections, ML-driven anomaly detection, or SOC
  integration is at `Initial`, not `Advanced`.
- **Severity**: high (cross-cutting; under-claim risk inverse).
- **Mitigation**: X.X7's cross-cutting prover requires (a)
  centralized log aggregation (LOOP-E.E1 streaming sink), (b)
  named detections (Sigma rules / Sentinel analytics / similar)
  with non-zero hit rate in trailing 30 days, (c) SOC alert
  workflow integration evidence (PagerDuty/Opsgenie/Jira tickets
  generated from detections). Coverage = active detections /
  required ZTMM detection set. Cross-references LOOP-E.E1 +
  LOOP-G.G2.
- **Status**: open.

### X-X42 — Visibility & Analytics SIEM cost + retention truncation

- **Description**: A SIEM-cost-driven retention truncation (90 days
  rather than full required retention) is a Visibility gap. The
  ZTA Tenet 7 ("The enterprise collects as much information as
  possible") presumes durable retention. Cost-control truncation
  caps the pillar.
- **Severity**: med.
- **Mitigation**: X.X7 reads retention configuration per SIEM /
  log sink. Threshold for `Advanced` = 365-day retention; for
  `Optimal` = 7-year retention (aligned with FedRAMP record
  retention). Cross-references LOOP-H.H1 long-term storage
  classifier (HOT/WARM/COLD tier movement preserves retention
  while controlling cost).
- **Status**: open.

### X-X43 — Visibility & Analytics PII redaction in logs

- **Description**: Detailed telemetry is in tension with privacy:
  PII in logs is a M-17-12 / SP 800-122 / GDPR concern. A SIEM
  without per-field redaction may capture customer PII at high
  volume + create incident-response exposure.
- **Severity**: med (cross-loop with M and P).
- **Mitigation**: X.X7 surfaces `pii_redaction_evidence_id` per
  Visibility & Analytics emit + cross-references LOOP-M.M2 PII
  inventory + LOOP-P.P1 user-activity-monitoring redaction. Runbook
  documents the per-field redaction pattern (mask credit-card,
  truncate SSN, hash username).
- **Status**: open.

### X-X44 — Visibility & Analytics threat intelligence integration

- **Description**: ZTMM v2.0 Visibility at Advanced/Optimal expects
  external threat intelligence fed into detection. CSPs commonly
  consume threat intel ad hoc without programmatic integration.
- **Severity**: med.
- **Mitigation**: X.X7 surfaces `threat_intel_feed_inventory`
  + `threat_intel_match_count_30d`. Threshold for `Advanced` =
  >= 2 feeds with matches in 30 days; for `Optimal` = >= 4 feeds.
  Cross-references CISA Known Exploited Vulnerabilities catalog +
  MITRE ATT&CK + commercial feeds.
- **Status**: open.

### X-X45 — Automation & Orchestration drift (manual exception cascade)

- **Description**: ZTMM v2.0 Automation & Orchestration cross-cutting
  at Advanced/Optimal expects automated policy enforcement + SOAR
  playbook automation. Operationally, every ZTA implementation
  accumulates "manual exception" cases — operator overrides applied
  outside the policy-as-code flow. Drift accumulates as exceptions.
- **Severity**: high (cross-cutting; under-detection risk).
- **Mitigation**: X.X7's prover reads (a) policy-as-code commit log
  vs PDP-resident policy hash (cf. X-X13), (b) manual-override audit
  log from PDP + IdP + EDR, (c) SOAR playbook execution log.
  Threshold for `Advanced` = manual-override-rate <= 5% of policy
  decisions; for `Optimal` = <= 1%. Cross-references LOOP-G.G2
  incident-response automation evidence.
- **Status**: open.

### X-X46 — Automation & Orchestration CI/CD security gates

- **Description**: M-22-09 Goal G33 + ZTMM Automation expect CI/CD
  pipelines with security gates (SAST / SCA / secrets-scanning /
  cosign signing). Common gap: gates exist but in audit-not-block
  mode, or are bypass-allowed for specific teams.
- **Severity**: high.
- **Mitigation**: X.X7 reads CI/CD config inventory (GitHub Actions
  workflows / GitLab CI / Jenkins jobs) + the actual block-rate vs
  audit-rate from the trailing 30 days. Threshold for `Advanced` =
  >= 75% gates block; for `Optimal` = >= 95%. Cross-references
  LOOP-J.J3.b (cosign signing) + LOOP-K (test artefact ingest).
- **Status**: open.

### X-X47 — Automation & Orchestration incident-response runbook automation

- **Description**: ZTMM Automation at Advanced/Optimal expects
  SOAR playbooks that automate IR steps (isolate compromised
  workload, revoke session, rotate credential). Common gap:
  runbooks exist as documents but aren't automated.
- **Severity**: med.
- **Mitigation**: X.X7 reads SOAR playbook inventory from
  Splunk SOAR / Cortex XSOAR / Tines / Torq / similar. Threshold
  for `Advanced` = >= 5 named playbooks with non-zero execution
  in trailing 90 days. Cross-references LOOP-G.G2 IR documentation
  + CIRCIA workflow.
- **Status**: open.

### X-X48 — Automation & Orchestration policy testing + chaos engineering

- **Description**: ZTMM Automation at Optimal expects policy
  testing — unit tests for OPA policies, integration tests for
  admission controller, periodic chaos engineering for resilience.
  Common gap: zero test coverage on policy code.
- **Severity**: med.
- **Mitigation**: X.X7 reads policy-code test coverage from
  CI run logs (OPA tests, Cedar test fixtures); threshold for
  `Optimal` = >= 80% policy-code coverage + at least 1 chaos
  experiment per quarter. Runbook documents the policy-test
  pattern.
- **Status**: open.

### X-X49 — Governance cross-cutting policy-as-code drift (cross-ref X-X13)

- **Description**: The Governance cross-cutting capability at
  Advanced/Optimal requires policy-as-code with signed bundles +
  drift detection. The X-X13 PDP drift scenario applies more
  broadly to Governance — every policy domain (identity, network,
  data) has the same drift risk.
- **Severity**: high.
- **Mitigation**: X.X7 aggregates drift signals across all PDPs
  + admission controllers + network-policy controllers + data-
  policy enforcement points; `governance_drift_index` = (drifted
  policy bundles) / (total policy bundles). Threshold for
  `Advanced` = <= 5% drift; for `Optimal` = <= 1%. Cross-references
  X-X13 specifically + LOOP-J.J3.b cosign for signing.
- **Status**: open.

### X-X50 — Governance role + responsibility documentation

- **Description**: ZTMM Governance at Advanced/Optimal expects
  documented roles (CISO / Zero Trust Lead / Pillar Owners) +
  RACI matrices. A CSP without documented ownership cannot
  legitimately attest Governance Optimal.
- **Severity**: med (documentation gap).
- **Mitigation**: X.X7 reads operator-supplied governance
  documentation reference from `zero-trust-config.yaml
  governance_documentation{}`; requires RACI matrix per pillar
  + named owner per capability. Cross-references LOOP-P insider-
  threat program documentation pattern.
- **Status**: open.

### X-X51 — Governance budget + funding evidence (M-22-09 §III.B)

- **Description**: M-22-09 §III.B requires agencies to incorporate
  ZTA into their budget submissions. For CSPs serving Federal
  customers, evidence of ZTA-aligned investment is a procurement
  signal. The scorecard does not directly emit budget data, but
  the Governance cross-cutting expects programmatic investment.
- **Severity**: low (signal only).
- **Mitigation**: Operator-supplied via `zero-trust-config.yaml
  governance_investment_summary{}`; recorded in the signed
  attestation envelope as advisory. No automated denominator.
- **Status**: open.

### X-X52 — Governance training + workforce skilling

- **Description**: ZTMM Governance + LOOP-P workforce security
  expect ZTA-specific training. CSPs commonly have generic
  security awareness training without ZTA-specific modules.
- **Severity**: low.
- **Mitigation**: Operator-supplied via `zero-trust-config.yaml
  governance_training_program{}`; cross-references LOOP-P.P3
  security awareness program slice.
- **Status**: open.

### X-X53 — Governance third-party / supply chain attestation cascade

- **Description**: Governance at Advanced/Optimal requires SCRM
  oversight of third-party providers. A CSP's ZTA posture is
  partly inherited from third-party SaaS dependencies; if those
  providers haven't attested ZTA themselves, the Governance
  capability has a downstream gap.
- **Severity**: med (cross-loop with LOOP-J + LOOP-W).
- **Mitigation**: X.X7 reads LOOP-W subprocessor screen + LOOP-J
  vendor SBOM signing; surfaces `third_party_zta_attestation_
  coverage`. Cross-references LOOP-W subprocessors-sheet schema.
- **Status**: open.

### X-X54 — Cross-loop dependency: LOOP-E.E1 streaming telemetry pipeline

- **Description**: X.X2..X.X6 all depend on LOOP-E.E1's streaming
  telemetry. If LOOP-E.E1 is degraded (broker outage, retention
  truncated, schema drift), every pillar emit reflects stale
  evidence. A naive aggregator might silently treat absence-of-data
  as Traditional rather than as `evidence-unavailable`.
- **Severity**: high.
- **Mitigation**: X.X2..X.X6 check `out/streaming-telemetry-
  health.json` (emitted by LOOP-E.E1) for the trailing-30-day
  window; if health is not green, the affected pillar emits
  `coverage:streaming-telemetry-unhealthy` + caps at the lowest
  evidence-supported stage. The scorecard envelope `evidence_
  health` field surfaces the dependency. Cross-references
  LOOP-E-RISKS.md.
- **Status**: open.

### X-X55 — Cross-loop dependency: LOOP-J.J3.b cosign verification chain

- **Description**: Application Workload pillar (X.X5) depends on
  LOOP-J.J3.b cosign verification. If cosign verification fails,
  the workload-provenance evidence is invalid. Same risk class as
  W-X34 (LOOP-W SBOM cosign dependency).
- **Severity**: high.
- **Mitigation**: X.X5 explicitly checks LOOP-J.J3.b's
  verification status; fails closed if any verification regression
  in trailing 30 days. Strict mode exits non-zero. Cross-references
  LOOP-J-RISKS.md.
- **Status**: open.

### X-X56 — Cross-loop dependency: LOOP-L CRM responsibility map

- **Description**: PDP/PEP separation evidence partly resides in
  the customer's authority boundary (per LOOP-L.L1 CRM). LOOP-X
  must consume the CRM responsibility map to know which evidence
  is CSP-owned vs customer-owned vs shared.
- **Severity**: med.
- **Mitigation**: X.X7 reads LOOP-L.L1's CRM responsibility map +
  surfaces per-capability `responsibility_provider` (CSP /
  customer / shared) in the scorecard. Capabilities marked
  `customer-owned` do not contribute to the CSP's stage but are
  surfaced as informational. Cross-references LOOP-L-RISKS.md.
- **Status**: open.

### X-X57 — Tracker Ed25519 signing-key rotation across attestation versions

- **Description**: X.X7 emits signed attestations periodically
  (rolling 30-day cadence, plus on material change). Multi-period
  attestation records persist indefinitely. Tracker resident-key
  rotation, AO role-holder rotation, or system-wide signing-key
  rotation across periods could invalidate prior-period attestation
  signatures during cross-period reporting.
- **Severity**: med.
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys`
  returning all historical keys keyed by `key_id`; reader cross-
  references each attestation record's `signing_key_id` against
  the registry. Pattern reused from LOOP-B-X3, LOOP-R-X4,
  LOOP-S-X6, LOOP-T-X24, LOOP-W-X23. Key rotation events written
  to `audit_log`; runbook documents.
- **Status**: open.

### X-X58 — Provenance schema drift across new LOOP-X emit artifacts

- **Description**: Every new emit artifact (`ztmm-catalog.json`,
  `ztmm-identity-pillar-evidence.json`,
  `ztmm-device-pillar-evidence.json`,
  `ztmm-network-pillar-evidence.json`,
  `ztmm-application-workload-pillar-evidence.json`,
  `ztmm-data-pillar-evidence.json`,
  `ztmm-scorecard-{period}.json`,
  `ztmm-scorecard-{period}.docx`,
  `dod-ztra-v2.0-attestation.json` (conditional)) must carry a
  `provenance` block per REO Rule 2.6.
  `scripts/check-provenance.mjs` enforces the schema (emitter,
  emittedAt, sourceCalls, signingKeyId). A missed block silently
  fails the slice.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via
  `check:provenance`; pattern reused from `core/inventory-coverage.
  ts`. Cross-references LOOP-B-X9, LOOP-R-X9, LOOP-S-X16,
  LOOP-T-X21, LOOP-W-X25. CHANGELOG entry per slice cites the
  provenance block contents.
- **Status**: open.

### X-X59 — REO Rule 1.8 `process.env.NODE_ENV === 'test'` branch creep

- **Description**: REO Rule 1.8 prohibits this branch in production
  code. New ZTMM evidence-aggregator infrastructure (per-pillar
  joiners, stage classifier, scorecard renderer, attestation
  signer) is exactly where developers reach for the test-short-
  circuit when injection seams are tricky.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal;
  tests inject seams via dependency-injected HTTP fetcher +
  filesystem helper + clock helper + cloud-SDK Proxy; CI gate is
  non-bypassable. Cross-references LOOP-B-X6, LOOP-R-X6, LOOP-S-X15,
  LOOP-T-X20, LOOP-W-X26.
- **Status**: open.

### X-X60 — Multi-tenant LOOP-X isolation deferred to LOOP-H.H3

- **Description**: All LOOP-X tracker tables omit a `tenant_id`
  column. When multi-CSO ships (H.H3), all need migration in a
  single cross-loop sweep. Same risk class as B-X15, R-X15,
  S-X21, T-X28, W-X38.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in `LOOP-X-SPEC.md §9 Open Questions`;
  H.H3 spec must enumerate every LOOP-X table; LOOP-X ships in
  single-tenant deployments only (documented in runbook). Cross-
  references LOOP-B-X15, LOOP-R-X15, LOOP-S-X21, LOOP-T-X28,
  LOOP-W-X38.
- **Status**: open.

---

## Per-slice risks

### X.X1 — ZTMM v2.0 pillar catalogue extractor

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| X.X1-1 | high | CISA ZTMM v2.0 PDF under HTTP redirect or revision change without notice | Extractor (`scripts/extract-ztmm-catalog.mjs`) downloads PDF + asserts SHA-256 against pinned hash; `REQUIRES-OPERATOR-INPUT: confirm-against-new-revision` on mismatch | open |
| X.X1-2 | high | ZTMM v2.0 vs v1.0 rubric drift (cross-ref X-X1) | `catalog_version = "ZTMM-v2.0-2023-04-11"` constant + `revision_pin`; CHANGELOG per refresh | open |
| X.X1-3 | med | OMB M-22-09 crosswalk inaccuracy (cross-ref X-X4) | `mapping_confidence` + `mapping_source` per row; low-confidence flags require operator review | open |
| X.X1-4 | med | DoD ZTRA v2.0 overlay drift (cross-ref X-X5) | Separate `data/dod-ztra-v2.0.json` catalogue; version constant; conditional emit gated by `dod_overlay: true` | open |
| X.X1-5 | low | Capability label translation between rubric versions | Translation table `data/ztmm-v1-to-v2-translation.json`; documented in CHANGELOG | open |
| X.X1-6 | med | Catalogue extractor non-deterministic ordering | Sort by `(pillar_id, function_id, capability_id, stage_id)`; deterministic emit | open |
| X.X1-7 | low | Operator override drift on capability mapping | `override_for_catalog_version` field; flagged for review on version bump | open |
| X.X1-8 | low | NIST SP 800-207A v1 → potential Rev 1 cross-reference drift | Cross-reference table version-pinned; CHANGELOG per refresh | open |
| X.X1-9 | low | Catalogue file size growth (300+ rows × 4 stages = 1200+ stage-rows) | JSON-line emit; bench at 10k stage-rows < 50ms load | open |
| X.X1-10 | med | Coverage-source registry add (`coverage_source: ztmm-catalog`) | `check:provenance` enforces; CHANGELOG entry per source addition | open |
| X.X1-11 | low | First-run bootstrap when no prior catalogue exists | `--first-catalog` flag opts into emit; CHANGELOG documents bootstrap | open |
| X.X1-12 | low | Catalogue retention policy (long-lived historical reference) | Retained 7 years per FedRAMP records retention; LOOP-H.H1 long-term tier | open |
| X.X1-13 | med | ZTMM v2.0 PDF only HTML; structured-data extraction fragile | Extractor uses pdf-text + page-anchored selectors; per-pillar table assertions; CI cron re-verifies | open |
| X.X1-14 | low | Bilingual / accessibility variants of capability labels | English-only at launch; future enhancement could add localisation | open |

### X.X2 — Identity pillar evidence aggregator

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| X.X2-1 | high | Phishing-resistant MFA coverage gap (cross-ref X-X16) | Coverage join over per-user MFA registration + per-session method; thresholds 95%/99%; test A10 | open |
| X.X2-2 | high | NPE / service-account coverage (cross-ref X-X17) | Separate NPE subset; static-long-lived → Traditional; OIDC-federated → promotion eligible; test A11 | open |
| X.X2-3 | med | Continuous-authentication false-pass (cross-ref X-X18) | Multi-signal requirement (>= 3) + mid-session re-eval + enforcement evidence; test A12 | open |
| X.X2-4 | med | Single-IdP concentration risk (cross-ref X-X15) | `identity_concentration_risk` flag surfaced; not a hard cap | open |
| X.X2-5 | high | Privileged access management gap (cross-ref X-X19) | JIT + session-recording + short-lived credential thresholds | open |
| X.X2-6 | med | Identity store consolidation (cross-ref X-X20) | Federation topology + count thresholds; operator override | open |
| X.X2-7 | high | Adapter rate-limit + auth churn across IdP APIs | Per-IdP rate-limit honored; backoff + retry; coverage:idp-throttled emit | open |
| X.X2-8 | med | IdP API schema migration (Okta v2 → v3, Azure Graph v1 → v2) | `idp_api_version` pinned per IdP; CHANGELOG per migration | open |
| X.X2-9 | high | Identity provenance preservation (per-event signing_key_id) | Tracker Ed25519 key registry (X-X57); per-event provenance | open |
| X.X2-10 | med | Stale session-log retention vs SIEM truncation | Cross-references LOOP-E.E1 retention; min 30-day floor required | open |
| X.X2-11 | low | Mobile-IdP integration (Apple ID / Google) for BYOD | Out-of-scope for first cut; documented as future enhancement | open |
| X.X2-12 | med | Cross-cloud IdP federation (Okta → AWS IAM + GCP Workspace + Azure AD) | Per-cloud federation contract enumeration; surfaces `cross_cloud_federation_map` | open |
| X.X2-13 | high | Break-glass account audit (over-permitted set undermines floor) | Break-glass cap (default 10); operator justifies > 10 via overrides.yaml | open |
| X.X2-14 | med | Workforce vs customer identity separation | Distinct stores required; pillar evidence emitted per population | open |
| X.X2-15 | low | Identity pillar emit size at 100k+ users | JSON-line emit; aggregation summarizes per-population; per-user detail in archived bundle | open |
| X.X2-16 | med | POA&M emit explosion on coverage gaps | Group by capability; one POA&M per (capability, gap-class); UI surfaces pillar-stage facet | open |

### X.X3 — Device pillar evidence aggregator

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| X.X3-1 | high | BYOD coverage gap (cross-ref X-X21) | managed_device_coverage join + thresholds 95%/75%; test A13 | open |
| X.X3-2 | med | Device attestation chain (TPM / measured boot) (cross-ref X-X22) | Per-device attestation evidence; thresholds 95%/90%/80% | open |
| X.X3-3 | high | EDR coverage + telemetry quality (cross-ref X-X23) | Installed/managed + telemetry-freshness join; thresholds 95%/99% | open |
| X.X3-4 | med | Mobile device parity (cross-ref X-X24) | Coverage denominator includes all form factors; operator override for exclusions | open |
| X.X3-5 | med | Firmware + supply-chain integrity (HBOM) (cross-ref X-X25) | HBOM threshold 50%; firmware telemetry 50%; runbook adoption roadmap | open |
| X.X3-6 | high | MDM API schema drift (Jamf, Intune, Workspace ONE) | Per-MDM API version pin; CHANGELOG per migration | open |
| X.X3-7 | med | Decommissioned-device tail (devices in MDM but offline 90+ days) | Decommission detection + exclusion from active denominator | open |
| X.X3-8 | high | Device-identity tie-back (cross-pillar with X.X2) | join on `device_fingerprint` + IdP session log; mismatch flags `unknown_device_session` | open |
| X.X3-9 | med | Container-only workloads (no traditional "device") | Cross-pillar with X.X5; documented in runbook | open |
| X.X3-10 | low | Embedded / IoT devices in agency-customer scope | Operator-supplied inventory via overrides.yaml; advisory pillar contribution | open |
| X.X3-11 | high | EDR vendor outage degrades pillar evidence | Coverage:edr-vendor-outage emit; alt evidence (host integrity logs) considered | open |
| X.X3-12 | med | Device-pillar provenance preservation | Tracker key registry (X-X57); per-device-event provenance | open |
| X.X3-13 | med | Device pillar UI surfaces stale data when MDM API throttled | Telemetry-freshness floor + UI banner | open |
| X.X3-14 | low | Cross-cloud workspace device aggregation (multiple Workspace ONE tenants) | Per-tenant aggregation; surfaces topology | open |

### X.X4 — Network pillar microsegmentation prover

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| X.X4-1 | high | Microsegmentation false-pass over-broad allow (cross-ref X-X26) | Per-rule blast-radius computation; flag over-broad; test A14 | open |
| X.X4-2 | high | East-west encryption gap (cross-ref X-X27) | Service-mesh mTLS coverage + non-mesh cloud-SDK evidence; thresholds 75%/95% | open |
| X.X4-3 | med | DNS encryption (cross-ref X-X28) | DoH/DoT + DNSSEC verification; thresholds; runbook | open |
| X.X4-4 | med | SD-perimeter / service-mesh sprawl (cross-ref X-X29) | `mesh_sprawl_index` flag; operator override for legitimate multi-mesh | open |
| X.X4-5 | high | Legacy crypto / TLS < 1.2 (cross-ref X-X30) | Per-endpoint scan; legacy-crypto-finding caps at Traditional | open |
| X.X4-6 | high | Cloud-SDK firewall scope schema (AWS SG vs GCP firewall vs Azure NSG) | Per-cloud canonical-rule normalizer; unit tests per cloud | open |
| X.X4-7 | med | K8s NetworkPolicy detection + coverage | NetworkPolicy aggregator per cluster; namespace-coverage threshold | open |
| X.X4-8 | high | Service-mesh adapter outage (Istio control plane) | coverage:service-mesh-control-plane-degraded emit; alt evidence considered | open |
| X.X4-9 | med | Per-account/per-VPC microsegmentation aggregation | Multi-account aggregation logic; per-account scorecard contribution | open |
| X.X4-10 | low | Custom/bespoke service-mesh (non-Istio/Linkerd/App Mesh) | Operator-supplied evidence via overrides.yaml | open |
| X.X4-11 | high | Network-pillar PDP/PEP separation (cross-ref X-X9) | PDP/PEP prover join; separated-PDP requirement | open |
| X.X4-12 | med | Egress-control gap (data-exfiltration vector) | Cross-references X-X39 + VPC Service Controls verification | open |
| X.X4-13 | med | API gateway in front of internal services + per-route auth | Per-route auth coverage check | open |
| X.X4-14 | low | IPv6 network coverage parity | v4 + v6 both audited; ipv6_coverage_finding flag | open |

### X.X5 — Application Workload pillar runtime-verification aggregator

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| X.X5-1 | high | Cosign verification false-pass (audit vs enforce) (cross-ref X-X31) | Admission-mode check + verification log scan; test A15 | open |
| X.X5-2 | med | Runtime-protection coverage (cross-ref X-X32) | Falco/CNAPP coverage threshold 75%/95% | open |
| X.X5-3 | high | API gateway + WAF coverage (cross-ref X-X33) | Per-endpoint WAF + block-mode evidence; thresholds 75%/95% | open |
| X.X5-4 | med | AI/ML workload provenance (cross-ref X-X34) | LOOP-O.O5 model-card index join; per-model artefact verification | open |
| X.X5-5 | high | Secrets management (no plaintext) (cross-ref X-X35) | Workload-manifest scan for inline secrets; cap at Initial | open |
| X.X5-6 | high | LOOP-J.J3.b cosign verification dependency (cross-ref X-X55) | Cosign verification status check; fail-closed strict mode | open |
| X.X5-7 | med | Admission controller (Kyverno / Gatekeeper / Sigstore PC) divergence | Per-controller config audit; CHANGELOG per migration | open |
| X.X5-8 | med | Lambda / Function-as-a-Service runtime evidence | Per-FaaS code signing + runtime-monitoring evidence | open |
| X.X5-9 | high | Workload SBOM provenance (cross-loop LOOP-J.J3) | SBOM signature verification per running workload | open |
| X.X5-10 | med | RBAC / ABAC scope tightness within workloads | Per-workload role-binding analysis (over-broad cluster-admin flag) | open |
| X.X5-11 | low | Multi-cluster aggregation logic | Per-cluster aggregator + multi-cluster sum; cluster-id provenance | open |
| X.X5-12 | med | Vulnerability scanning coverage (image + runtime) | LOOP-J.J2 + LOOP-E.E2 coverage join | open |
| X.X5-13 | high | Workload-pillar PDP/PEP separation (cross-ref X-X9) | Admission controller as PEP; OPA/Gatekeeper as PDP; separation evidence | open |
| X.X5-14 | med | Build-time signing key rotation (cosign root) | LOOP-J.J3.b cosign root fingerprint provenance | open |

### X.X6 — Data pillar classification + provenance aggregator

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| X.X6-1 | high | Data classification drift (cross-ref X-X36) | Cloud DLP + tag + catalogue cross-check; drift-finding caps at Initial | open |
| X.X6-2 | high | KMS / CMK rotation + customer-managed key coverage (cross-ref X-X37) | Per-resource CMK + rotation verification; thresholds 95%/99% | open |
| X.X6-3 | high | In-transit encryption (cross-ref X-X38) | TLS enforcement per data store + reused X-X27 service-mesh evidence | open |
| X.X6-4 | high | DLP + egress monitoring (cross-ref X-X39) | VPC Flow Log coverage 95%; egress-tooling inventory | open |
| X.X6-5 | med | Data lifecycle + retention (cross-ref X-X40) | Lifecycle-policy enforcement coverage; thresholds 75%/95% | open |
| X.X6-6 | high | PII / PHI / CUI inventory cross-ref (LOOP-M + LOOP-L) | LOOP-M.M2 PII inventory join + LOOP-L.L1 CRM data-handling map | open |
| X.X6-7 | med | DLP false-positive rate degrades coverage signal | Per-finding confidence band; only "high confidence" findings count toward drift cap | open |
| X.X6-8 | med | Data-pillar PDP/PEP separation for data-access decisions | Per-query authorization evidence (BigQuery DCL, Redshift RBAC, Snowflake masking policies) | open |
| X.X6-9 | high | Encryption-key compromise + rotation incident | Cross-loop with LOOP-G.G2; pillar emits `key_compromise_event` advisory | open |
| X.X6-10 | med | Cross-cloud data-replication encryption + integrity | Per-replication-link encryption + integrity hash evidence | open |
| X.X6-11 | low | Backup / DR data encryption parity | Backup-target encryption verification | open |
| X.X6-12 | med | Data-pillar PQC readiness (cross-loop LOOP-R) | Per-data-store PQC inventory; threshold defers to LOOP-R | open |
| X.X6-13 | high | Customer-managed key escrow vs CSP-controlled key escrow | Per-key escrow provenance; surfaces in scorecard | open |
| X.X6-14 | med | Data-pillar audit-log integrity (cross-ref X-X14) | Append-only sink + hash-chain + signing-key requirement | open |

### X.X7 — Pillar-stage scorecard + signed attestation + .docx emitter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| X.X7-1 | high | Pillar score inflation (cross-ref X-X2) | stage_rationale + supporting_evidence_ids + coverage_percentage; thresholds; test A1 | open |
| X.X7-2 | high | OMB M-22-09 alignment summary (cross-ref X-X4) | Crosswalk emit + .docx appendix; mapping_source + confidence | open |
| X.X7-3 | high | Self-attestation vs control-assessment confusion (cross-ref X-X8) | Disclaimer block in envelope + .docx cover; JSON schema asserts | open |
| X.X7-4 | high | PDP/PEP separation evidence (cross-ref X-X9, X-X10) | Aggregate from X.X2/X.X4/X.X5/X.X6; capability ceiling per separation | open |
| X.X7-5 | high | Visibility & Analytics telemetry quality (cross-ref X-X41) | Active-detection + SOC integration check; thresholds | open |
| X.X7-6 | high | Automation drift / manual override rate (cross-ref X-X45) | Per-domain manual-override audit log read; thresholds 5%/1% | open |
| X.X7-7 | high | Governance policy-as-code drift (cross-ref X-X49) | Aggregate drift index across PDPs; thresholds 5%/1% | open |
| X.X7-8 | med | Rolling-30-day attestation window (cross-ref X-X7) | valid_until = signed_at + 30d; LOOP-Q badge consumer enforces | open |
| X.X7-9 | high | Tracker Ed25519 signing-key rotation (cross-ref X-X57) | GET /api/sign/public-keys registry; per-attestation signing_key_id | open |
| X.X7-10 | high | Repository tampering of attestation envelope | Signed envelope + tracker audit log + hash chain | open |
| X.X7-11 | med | Per-period emit explosion (12 monthly + 1 annual + N material-change) | Tracker aggregation by period; one .docx per renewal | open |
| X.X7-12 | high | Officer sign-off via WebAuthn vs server-side keys | Server-side first cut; WebAuthn follow-up; cross-ref R-X11 | open |
| X.X7-13 | med | DoD ZTRA v2.0 dual-emit pattern (cross-ref X-X5) | Conditional dual-emit; shared evidence index | open |
| X.X7-14 | med | Marketplace badge format change (LOOP-Q.Q1) | Signed JSON additive; backward-compat | open |
| X.X7-15 | low | Scorecard .docx file size (5MB warn, 25MB fail) | Per-period docs ~50-200KB; warn/fail thresholds documented | open |
| X.X7-16 | high | Tracker schema migration on existing installs | Additive CREATE TABLE IF NOT EXISTS; CHANGELOG documents | open |
| X.X7-17 | med | Submission bundle role table updates | tests/core/submission-bundle.test.ts pins; CHANGELOG lists final inventory | open |
| X.X7-18 | med | Multi-tenant deferred (cross-ref X-X60) | LOOP-H.H3 sweep + single-tenant deploy | open |

---

## External dependencies that may change

### Federal-Government strategy + standards

- **OMB M-22-09 — Moving the U.S. Government Toward Zero Trust
  Cybersecurity Principles (Jan 26 2022)** —
  https://zerotrust.cyber.gov/federal-zero-trust-strategy/ —
  binding on Federal civilian Executive Branch agencies. Sets
  FY24 deadlines + 24-month obligations measured from Jan 26 2022.
  Specific goals labelled by pillar in M-22-09 §III. The strategy
  page is the canonical landing URL; the underlying memo PDF is
  available via OMB's M-series archive at
  https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf.
- **CISA Zero Trust Maturity Model v2.0 (Apr 11 2023)** —
  https://www.cisa.gov/zero-trust-maturity-model — replaces v1.0
  (Aug 31 2021). 5 pillars + 3 cross-cutting capabilities + 4-stage
  rubric (Traditional, Initial, Advanced, Optimal). Errata work
  ongoing; horizon v3.0 unannounced as of 2026-06-07.
- **NIST SP 800-207 — Zero Trust Architecture (Aug 2020, final)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf —
  defines PDP/PEP architecture, 7 ZTA tenets, ZTA deployment
  variants. The foundational publication; widely cited by M-22-09
  + ZTMM.
- **NIST SP 800-207A — A Zero Trust Architecture Model for Access
  Control in Cloud-Native Applications in Multi-Cloud Environments
  (Sep 2023)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf —
  microsegmentation + service-mesh patterns; cited by ZTMM v2.0
  Network pillar.
- **DoD Zero Trust Reference Architecture v2.0 (Sep 2022)** —
  available via DISA https://dodcio.defense.gov/Library/ — 7
  pillars + 152 Activities + 45 Capabilities; relevant only when
  `dod_overlay: true`.
- **DoD Zero Trust Strategy (Oct 21 2022)** —
  https://dodcio.defense.gov/Portals/0/Documents/Library/DoD-ZTStrategy.pdf —
  companion to DoD ZTRA v2.0.
- **CISA "Implementing Phishing-Resistant MFA" (Oct 31 2022)** —
  https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf
  — defines phishing-resistant MFA methods recognized for M-22-09
  Goal G3.
- **CISA Software Acquisition Guide (Aug 2024)** —
  https://www.cisa.gov/resources-tools/resources/software-acquisition-guide-government-enterprise-consumers —
  procurement-side companion; cited in Application Workload pillar
  runbook.
- **NIST SP 800-53 Rev 5 Errata (Dec 2023)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf —
  control-family cross-references in ZTMM crosswalk.
- **NIST CSF v2.0 (Feb 26 2024)** —
  https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf —
  informative references to ZTA practices; future crosswalk overlay
  potential.

### Federal-Government infrastructure + APIs

- **CISA Known Exploited Vulnerabilities catalog** —
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog —
  threat-intelligence feed cited by Visibility & Analytics
  cross-cutting.
- **Federal CIO Council Zero Trust Architecture playbook** —
  https://www.cio.gov/ — agency-specific implementation guides;
  referenced by runbook.
- **GAO-23-105424 — Federal Agencies Need Stronger Implementation
  of Cybersecurity Practices (May 2023)** —
  https://www.gao.gov/products/gao-23-105424 — audit of M-22-09
  progress; cited in runbook.

### Statute / regulation / directive

- **Executive Order 14028 — Improving the Nation's Cybersecurity
  (May 12 2021)** —
  https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/ —
  parent EO that authorizes M-22-09 + the SSDF + the
  attestation-collection regime.
- **National Cybersecurity Strategy (Mar 2023)** —
  https://www.whitehouse.gov/wp-content/uploads/2023/03/National-Cybersecurity-Strategy-2023.pdf —
  reinforces ZTA mandate at the strategy level.

### Open-source ecosystem dependencies

- **Sigstore / cosign / Rekor** — `cosign verify` chain for
  workload provenance; LOOP-J.J3.b parent dependency.
- **Open Policy Agent + Cedar** — canonical PDP examples; runbook
  references.
- **Istio + Linkerd + AWS App Mesh** — canonical service-mesh
  implementations; X.X4 reads control planes.
- **CrowdStrike + SentinelOne + Microsoft Defender + Carbon Black**
  — canonical EDR vendors; X.X3 reads APIs.
- **Splunk + Elastic + Microsoft Sentinel** — canonical SIEM
  platforms; X.X7 Visibility & Analytics reads.
- **HashiCorp Vault + AWS Secrets Manager + GCP Secret Manager +
  Azure Key Vault** — canonical secrets stores; X.X5 reads
  inventories.

---

## Resolved risks (historical)

> None as of 2026-06-07. Resolved risks remain in the register
> with `status=resolved` and a resolution note referencing the
> commit + slice that resolved them.

---

## Resume-from-fresh-session checklist

A fresh session resuming LOOP-X work should:

1. **Read `cloud-evidence/CLAUDE.md`** — REO standard + Slice-completion
   directive.
2. **Read `cloud-evidence/docs/STATUS.md`** — find the "Overall →
   Next priority" line + the LOOP-X status table.
3. **Read `docs/loops/LOOP-X-SPEC.md`** — high-level loop context +
   slice rationale.
4. **Read the specific `docs/slices/X/X.XN.md`** for the slice you
   are working — deep-context per-slice doc with Implementation log
   of prior sessions.
5. **Read THIS FILE (`LOOP-X-RISKS.md`)** — all cross-cutting +
   per-slice risks active during the work.
6. **Read `docs/SLICE-COMPLETION-PROCEDURE.md`** — 7-step procedure.
7. **Cross-reference companion risks registers** when the slice
   touches a cross-loop dependency (LOOP-E, LOOP-J, LOOP-L, LOOP-O,
   LOOP-P, LOOP-B, LOOP-S).
8. **Read `docs/DEPENDENCY-GRAPH.md`** to confirm the slice is
   unblocked.
9. **Begin work** under the REO standard; update the Implementation
   log in the per-slice doc at every commit boundary.
10. **At completion**, follow the 7-step procedure + push to
    origin/main + verify with `git log --oneline -3`.

If during work a new risk is discovered, ADD a new row to this
register IN THE SAME COMMIT that surfaces the risk. The register
is the on-disk archaeological record of the loop's risk surface;
future sessions consult it before re-tracing ground.

---

> END OF LOOP-X — Risks Register
