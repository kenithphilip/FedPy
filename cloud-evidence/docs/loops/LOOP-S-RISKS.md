# LOOP-S — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.
> Severity: high = ship-blocking; med = should fix in-loop; low = file
> as follow-up.

> Authoritative companion to `docs/loops/LOOP-S-SPEC.md` and the
> per-slice docs at `docs/slices/S/S.S[1-3].md`. Read those for context
> before acting on any risk here.

> **CONDITIONAL GATE**: LOOP-S applies ONLY when the CSP has at least
> one DoD-prime customer (DFARS Subpart 204.73 applicable). For
> civilian-agency-only CSPs, LOOP-S is a no-op and none of these risks
> activate. Every risk below carries an implicit
> "WHEN LOOP-S IS ACTIVE" precondition.

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in LOOP-S)

### S-X1 — DoD CIO Memorandum (Dec 21 2023) PDF gated by 403 on anonymous fetch

- **Description**: The DoD CIO Memorandum "FedRAMP Moderate Equivalency
  for Cloud Service Providers in Support of the DoD" (Dec 21 2023) is
  published via the DoD CIO library and may return HTTP 403 to
  anonymous fetches. The memo is the source of the verbatim
  Equivalency Letter language S.S3 must reproduce + the BoE
  requirements list. Without the PDF locally available, S.S3 cannot
  pin verbatim quotes.
- **Severity**: high (S.S3 blocker).
- **Mitigation**: Implementer downloads the PDF manually to
  `cloud-evidence/docs/sources/dod-cio-memo-fedramp-equivalency-2023-12-21.pdf`
  before writing S.S3 quote constants. The emitter's docstring carries
  a `REQUIRES-OPERATOR-INPUT: confirm-against-dod-cio-memo-pdf`
  marker on the constants until the PDF is verified verbatim. Visible
  to `check:reo` reviewers; not silent.
- **Status**: open.

### S-X2 — DoD Cloud Computing SRG v1r4 PDF reachability

- **Description**: The DoD CC SRG v1r4 PDF
  (https://dodcio.defense.gov/Portals/0/Documents/DD/CloudComputingSRG_v1r4.pdf)
  defines IL2/IL4/IL5/IL6 boundary conditions S.S3 references for
  `operating_impact_level`. If the URL returns 403 or moves, the
  manifest's section reference becomes stale.
- **Severity**: med (S.S3 documentation, not emit-blocker).
- **Mitigation**: Download PDF to
  `cloud-evidence/docs/sources/dod-cc-srg-v1r4.pdf`; cite section
  numbers verbatim in the manifest's `operating_impact_level_rationale`
  field. Periodically re-verify URL via CI link-check.
- **Status**: open.

### S-X3 — NIST 800-171 Rev 3 Appendix C .xlsx column layout drift

- **Description**: S.S1's extraction script reads NIST's published
  Appendix C .xlsx. Column order, sheet name, or row format could
  change in a future NIST revision (Rev 4, dot-releases). A silent
  format drift would emit an empty catalog and downstream a
  cross-walk full of `requires-operator-input`.
- **Severity**: high (S.S1 emit silently broken if undetected).
- **Mitigation**: Extraction script asserts expected column headers +
  expected row count (≥110 requirements + 17 distinct families) +
  throws typed error with a remediation message ("Re-fetch
  https://csrc.nist.gov/pubs/sp/800/171/r3/final Appendix C and
  re-run scripts/extract-800-171-r3.mjs"). CI runs the extraction
  + count assertion on every PR.
- **Status**: open.

### S-X4 — DC3 ICF v3.0 schema evolution

- **Description**: DC3 may publish ICF v3.1 with added fields. S.S2's
  emitter pins `schema_version: '3.0'`; a prime that requires v3.1
  would reject the report.
- **Severity**: med.
- **Mitigation**: `schema_version` is a top-level field on the typed
  interface; bumping it is a contained change. CHANGELOG documents
  the active version. Operator runbook documents how to bump.
- **Status**: open.

### S-X5 — DIBNet portal authentication procurement lag

- **Description**: S.S2 produces the ICF artifact but the operator
  submits via the DIBNet portal, which requires DoD-approved
  Medium-Assurance ECA or DoD CAC. Procurement can take weeks. If an
  incident occurs before credentials are in place, the 72h deadline
  cannot be met regardless of S.S2's correctness.
- **Severity**: high (operational, not code).
- **Mitigation**: LOOP-S.S2 ship checklist explicitly includes
  "DIBNet credentials procured" as a pre-flight. Operator runbook
  documents the procurement steps. Tracker UI banner reminds the
  operator if the first incident is created without a recorded
  credential.
- **Status**: open.

### S-X6 — Tracker Ed25519 signing-key rotation

- **Description**: S.S2 (incidents + submissions), S.S3 (attestations
  + runbook sections) all sign records with the tracker-resident
  Ed25519 key. If the tracker rotates without exposing a historical
  key registry, snapshots written under the old key fail verification.
  Same risk class as LOOP-B B-X3.
- **Severity**: med (impacts S.S2, S.S3).
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys`
  returning ALL historical public keys keyed by `key_id`; reader
  cross-references each record's `signing_key_id` against the
  registry. Key rotation events written to `audit_log`; runbook
  documents the rotation procedure. Inherits the same fix as B-X3 —
  if B-X3 ships first, S inherits it.
- **Status**: open.

### S-X7 — CUI sub-category taxonomy drift vs NARA Registry

- **Description**: S.S1 reads `inventory.assets[].fedramp_cui_category`
  tags + S.S2's `affected_cui_categories[]` field references the NARA
  CUI Registry. NARA updates the registry; operator-tagged values can
  drift from current categories.
- **Severity**: med.
- **Mitigation**: Tag values carried verbatim; mismatches surface as
  `REQUIRES-OPERATOR-INPUT: unknown-cui-category-<value>` in the
  xlsx (S.S1) + ICF report (S.S2). Operator runbook documents the
  NARA registry URL + periodic re-verification cadence.
- **Status**: open.

### S-X8 — CSP-officer identity vs IDP role mapping

- **Description**: S.S3 requires a user with `officer` role to sign the
  Equivalency Letter. The tracker's RBAC supports custom roles, but
  the operator's identity provider (Okta / Azure AD / GitHub OIDC)
  may not map any user to `officer`. Without that mapping, the
  Equivalency Letter has no defensible signer.
- **Severity**: high (S.S3 ship-blocker).
- **Mitigation**: First-boot prompt requires admin to assign at least
  one `officer` role; tracker UI's "Settings → Roles" page documents
  the mapping; runbook explains IDP-side configuration. CHANGELOG
  calls out the role requirement.
- **Status**: open.

### S-X9 — 3PAO availability for DFARS-equivalency assessments

- **Description**: Not every FedRAMP-recognized 3PAO has DFARS-
  specific assessment experience. S.S3 requires the 3PAO letter as
  operator-uploaded evidence; engaging a 3PAO is out of the system's
  authority and can take months.
- **Severity**: high (S.S3 ship-blocker, operational).
- **Mitigation**: LOOP-S ship checklist requires "3PAO engagement
  contracted + assessment letter on file" pre-flight. Runbook lists
  3PAOs with documented DFARS-equivalency experience (operator
  responsibility to maintain). Tracker UI hint surfaces missing
  3PAO letter.
- **Status**: open.

### S-X10 — Annual attestation expiration without re-engagement

- **Description**: DoD CIO Memo expects attestations to be refreshed
  at least annually. S.S3's enforcer flips status to `expired` at
  the 365-day mark; if the operator doesn't renew, the bundler
  starts refusing to ship a DFARS package. Without a clear re-
  engagement workflow with the 3PAO, the operator may face a
  service-delivery gap.
- **Severity**: med.
- **Mitigation**: Enforcer emits notification 30 days BEFORE
  expiration (not just at expiration), via `core/notify.ts`; UI
  surfaces the countdown; runbook documents the 90-day re-engagement
  lead time.
- **Status**: open.

### S-X11 — Coordination drift between S.S2 (DFARS) and M.M4 (PII)

- **Description**: A single incident affecting both CUI and PII
  triggers BOTH a DFARS DC3 report (S.S2, 72h) and a PII breach
  notification (M.M4, varies — state laws + GDPR equivalent + FAR
  52.224-2). The operator can mis-prioritize and miss a deadline.
- **Severity**: med.
- **Mitigation**: Tracker UI surfaces both deadlines side-by-side
  with separate countdowns; no coalescing; the S.S2 emitter logs a
  coordination notice when `pii_affected && (cui_affected ||
  cdi_affected)`; runbook documents the dual-track procedure.
- **Status**: open.

### S-X12 — 90-day media preservation cost + storage classifier
  interaction

- **Description**: DFARS 7012(e) requires 90-day media preservation
  for affected systems. Storage costs accumulate per incident.
  LOOP-H's long-term-storage classifier (H.H1) reads
  `retention_until` on artifacts but may route to a tier that's
  cheap-write / expensive-read (Glacier Deep Archive) — read during
  forensic analysis could be slow.
- **Severity**: low.
- **Mitigation**: S.S2's `dfars_incident_artifacts.retention_until`
  is preserved; H.H1 reads it. LOOP-H roadmap notes that
  DFARS-tagged artifacts should route to a tier with restore SLA
  ≤ 12h. Documented in runbook.
- **Status**: open.

### S-X13 — IL5-equivalent claim without High-baseline + DoD overlays

- **Description**: A CSP that mistakenly claims IL5-equivalent in
  S.S3 without the underlying FedRAMP High package + DoD overlays
  is materially mis-representing its security posture. The DoD CC
  SRG v1r4 §5 is explicit that IL5 requires High + DoD overlays.
- **Severity**: high (legal exposure for the CSP).
- **Mitigation**: Defense-in-depth — BOTH DB
  `operating_impact_level='IL5-equivalent'` AND CLI
  `--confirm-il5` flag required; UI warning + officer second
  sign-off required; emitter additionally requires evidence of
  High-baseline benchmark (control-benchmark.json with `level: 'High'`)
  before allowing the claim.
- **Status**: open.

### S-X14 — REO Rule 4 violation: auto-submit to DIBNet

- **Description**: A developer might be tempted to add auto-submit
  to DIBNet for "convenience". This is a REO Rule 4 violation (the
  submission is a real human action requiring a DoD-approved
  credential that the system does not — and must not — hold).
- **Severity**: high (REO violation; CI must reject).
- **Mitigation**: S.S2 tests include `it('does NOT auto-submit to
  DIBNet (REO Rule 4)')` which asserts no HTTPS call to
  `dibnet.dod.mil`. CI gate is non-bypassable. Documented in
  CLAUDE.md REO standard as a worked example.
- **Status**: open.

### S-X15 — REO Rule 1.8 NODE_ENV branch creep

- **Description**: REO Rule 1.8 prohibits
  `process.env.NODE_ENV === 'test'` in production code. New tracker
  routes + emitter signing paths are exactly where developers reach
  for that shortcut.
- **Severity**: high (REO violation).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal;
  tests inject seams via dependency-injected HTTP fetcher + file
  system helper. CI gate is non-bypassable.
- **Status**: open.

### S-X16 — Provenance schema drift across new emit artifacts

- **Description**: S.S1 (`dfars-crosswalk.json`), S.S2
  (`dfars-incident-report-*.json`), S.S3
  (`dfars-equivalency-manifest.json`) all emit JSON with
  `provenance` blocks per REO Rule 2.6. A missed block fails the
  slice. Same risk class as B-X9.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via
  `check:provenance`; pattern reused from `core/inventory-coverage.ts`;
  CHANGELOG entry per slice cites the provenance block contents.
- **Status**: open.

### S-X17 — Submission-bundle role count growth + nested archive

- **Description**: LOOP-S adds 6 new roles to
  `submission-bundle.ts:WELL_KNOWN`
  (dfars-crosswalk-json, dfars-crosswalk-xlsx,
   dfars-incident-report-bundle, dfars-equivalency-letter-docx,
   dfars-equivalency-manifest-json, dfars-equivalency-runbook-docx)
  PLUS a nested archive (`dfars-equivalency-package.zip`). Role
  collisions or filename collisions would corrupt the bundle.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the
  role table; per-slice tests assert presence; CHANGELOG entry for
  S.S3 lists the final role inventory at loop close.
- **Status**: open.

### S-X18 — Tracker schema migration on existing installs

- **Description**: LOOP-S adds 5 new tables (`dfars_incidents`,
  `dfars_incident_submissions`, `dfars_incident_artifacts`,
  `dfars_equivalency_attestations`, `dfars_equivalency_runbook_sections`).
  Existing tracker installs have user data — migrations must be
  additive only.
- **Severity**: high (REO violation if not handled).
- **Mitigation**: All five tables are additive `CREATE TABLE IF NOT
  EXISTS`; CHANGELOG documents the upgrade path; smoke test on a
  copy of a production DB; no DROP / ALTER COLUMN under any
  circumstance in LOOP-S; future H.H3 multi-tenant work batches all
  cross-loop migrations including these.
- **Status**: open.

### S-X19 — Subcontractor / subprocessor flow-down per DFARS 7012(m)

- **Description**: DFARS 7012(m) requires flow-down of the clause
  to subcontractors handling CDI. The CSP's subprocessors are a
  similar relationship. If a subprocessor has a CUI-affecting
  incident, the CSP must record + potentially report it; LOOP-S
  does not currently model multi-party incident attribution.
- **Severity**: med (operational gap).
- **Mitigation**: S.S2's `dfars_incidents.description` field can
  carry attribution narrative; LOOP-J.J1 (Subprocessor Risk
  Register) emits a subprocessor incident inventory; runbook
  documents the operator-side coordination. A future enhancement
  could add structured subprocessor-source fields.
- **Status**: open.

### S-X20 — CMMC vs DFARS-equivalency confusion

- **Description**: An operator may believe LOOP-S satisfies CMMC L2
  certification. It does NOT — CMMC L2 requires a C3PAO assessment
  + eMASS / CMMC PIEE submission. Without explicit scope guarding,
  the operator may ship LOOP-S artifacts as if they were CMMC L2
  evidence.
- **Severity**: med (misuse risk).
- **Mitigation**: Every S-slice docstring + every CHANGELOG entry
  for LOOP-S opens with a scope disclaimer ("LOOP-S addresses
  DFARS 252.204-7012 cloud equivalency; it does NOT address CMMC
  certification"). Runbook documents the distinction. Marketplace
  metadata (LOOP-Q.Q1) `dod_equivalency: true` does NOT imply
  `cmmc_l2: true`.
- **Status**: open.

### S-X21 — Multi-tenant DFARS isolation deferred to LOOP-H.H3

- **Description**: All five LOOP-S tables omit a `tenant_id` column.
  When multi-CSO ships (H.H3), all five need migration in a single
  cross-loop sweep. Same risk class as B-X15.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in `LOOP-S-SPEC.md` §6 Open Questions;
  H.H3 spec must enumerate every LOOP-S table; LOOP-S ships in
  single-tenant deployments only (documented in runbook).
- **Status**: open.

### S-X22 — OSCAL chain interaction (POA&M, AR, AP) when DFARS active

- **Description**: When DFARS is active, the S.S1 crosswalk reads
  `out/poam.json` + `out/control-benchmark.json` for evidence
  pointers. If the FedRAMP package re-emits mid-run and the
  pointers become stale, the crosswalk references dead UUIDs.
- **Severity**: low (run-order is deterministic).
- **Mitigation**: Orchestrator pins the run order: POA&M emit →
  control-benchmark → DFARS crosswalk → DFARS attestation → bundle.
  Each emitter writes once; downstream reads only after upstream
  completes. Documented in orchestrator.ts block comment.
- **Status**: open.

### S-X23 — POA&M XML emitter coverage for DFARS-specific evidence

- **Description**: `core/oscal-xml.ts` projects POA&M JSON to XML.
  If LOOP-S adds new prop names to the OSCAL POA&M (it does NOT in
  this LOOP design, but a future slice might), they need to survive
  the JSON→XML pipeline. Same risk class as B-X14.
- **Severity**: low (LOOP-S design does not add new POA&M props).
- **Mitigation**: LOOP-S emits its own JSON / docx / xlsx artifacts;
  does NOT modify OSCAL POA&M emission. If a future enhancement
  adds POA&M props, the LOOP-B pattern (per-prop test +
  `core/oscal-validate.ts` re-validation) applies.
- **Status**: open.

### S-X24 — Test count expectations / CI thresholds

- **Description**: LOOP-S adds ≥65 new tests across cloud-evidence
  + tracker. Existing CI may have hard-coded "expected test count"
  assertions or coverage thresholds that need bumping. Same risk
  class as B-X13.
- **Severity**: low.
- **Mitigation**: Per slice, the implementing session updates any
  test-count assertion; CHANGELOG entries cite the new totals;
  STATUS.md "Overall → tests" line bumped atomically with each
  slice ship.
- **Status**: open.

### S-X25 — `DFARS_ENABLED` config flag UI gating drift

- **Description**: The tracker UI hides DFARS routes when
  `DFARS_ENABLED=false`. If a developer adds a new component that
  loads DFARS data without checking the flag, civilian-only tenants
  could see the noise. The reverse — a DoD-prime tenant with the
  flag accidentally off — would hide the operator's required
  workflow.
- **Severity**: med.
- **Mitigation**: Single source of truth — `config.dfarsEnabled`
  feature flag exposed via a React context provider; every DFARS
  component reads from the context; UI tests assert hide/show
  behavior in both directions.
- **Status**: open.

### S-X26 — Inventory CUI tagging absent on existing fleet

- **Description**: S.S1 requires
  `inventory.assets[].data_classification === 'cui'` to gate the
  crosswalk. Real CSPs may not have back-tagged CUI assets when
  they first onboard a DoD-prime customer. The crosswalk emits
  `coverage:skipped` honestly, but the prime gets an empty
  cui_categories[] view. Same risk class as B-X11.
- **Severity**: med (correctness signal, not a blocker).
- **Mitigation**: `coverage:skipped` is observable in the run log;
  documented in operator runbook with example tagging commands per
  provider (AWS `aws ec2 create-tags`, GCP `gcloud labels`, Azure
  `az tag`).
- **Status**: open.

---

## Per-slice risks

### S.S1 risks

#### S-S1-1 — 800-171 Rev 2 vs Rev 3 ambiguity

- **Description**: Some prime contracts still cite NIST 800-171
  Rev 2 by clause. Rev 3 (May 2024) re-organized families and added
  SR/PL/PM. A Rev 2 prime reading a Rev 3 crosswalk may be
  confused.
- **Severity**: low.
- **Mitigation**: S.S1 ships Rev 3 only; the operator's runbook
  documents the manual gap; future enhancement could add Rev 2
  catalog + dual-rev output. CHANGELOG opens with "Crosswalk
  expressed against NIST SP 800-171 Rev 3 (May 2024)".
- **Status**: open.

#### S-S1-2 — PM family rollup ambiguity

- **Description**: PM (Program Management) family contains
  controls typically organization-wide, not system-specific. A
  per-system crosswalk's status for PM is ambiguous.
- **Severity**: low.
- **Mitigation**: PM family entries roll up to
  `status='covered-by-organization'` with a tracker pointer to the
  organization-wide artifact (e.g. organization-wide ISMS document);
  documented in S.S1 spec docstring. UI tooltip explains.
- **Status**: open.

### S.S2 risks

#### S-S2-1 — Late discovery vs occurrence timing

- **Description**: The 72-hour clock starts at discovery, not
  occurrence. An incident discovered weeks after it occurred has
  the same 72-hour window from discovery; this is correct per
  DFARS but may surprise operators.
- **Severity**: low.
- **Mitigation**: Tracker UI prominently shows discovered_at vs
  occurred_at; deadline countdown is from discovered_at; runbook
  documents.
- **Status**: open.

#### S-S2-2 — Simultaneous incidents

- **Description**: Multiple related incidents in a single attack
  may need linked tracking. S.S2's model is one report per
  incident record.
- **Severity**: low.
- **Mitigation**: Tracker supports a "related" relationship
  between records; emitter outputs separate JSON per incident.
- **Status**: open.

### S.S3 risks

#### S-S3-1 — DoD CIO Memo template revision

- **Description**: DoD CIO may publish a successor memo with
  updated Equivalency Letter language. The current template
  version-pin will become stale.
- **Severity**: med.
- **Mitigation**: Letter renderer version-pins the template;
  CHANGELOG documents the active template version; operator
  updates `templates/dfars-equivalency-letter.template.json` when
  DoD CIO publishes new memo. CI could optionally check the DoD
  CIO library URL via a slow-cadence link-check.
- **Status**: open.

#### S-S3-2 — Per-prime customized letters

- **Description**: A single attestation may need a personalized
  cover letter per prime customer. S.S3 ships a single letter; a
  future enhancement may add `--per-prime-letters`.
- **Severity**: low (enhancement, not blocker).
- **Mitigation**: Open question Q5 in S.S3.md; deferred to a
  follow-up slice.
- **Status**: open.

#### S-S3-3 — Material-change re-attestation timing

- **Description**: DoD CIO Memo expects re-attestation within 30
  days of material change. S.S3 supports manual re-attestation
  (operator creates new row) but does not auto-detect material
  changes.
- **Severity**: med.
- **Mitigation**: Operator runbook documents the material-change
  triggers (e.g. new prime customer, change in 3PAO, change in
  operating impact level, change in cso_name); tracker UI prompts
  re-attestation when relevant fields change. Future enhancement
  could auto-detect via diff against prior attestation.
- **Status**: open.

---

## Resolution log

When a risk is resolved, add a line here citing the slice + commit
that resolved it. Mirrors LOOP-B-RISKS.md pattern.

| Risk | Resolved by | Commit | Date |
|---|---|---|---|
| _(none yet)_ | | | |

---

## Appendix — when does LOOP-S apply?

LOOP-S applies when ALL of the following are true:

1. The CSP has at least one customer that holds a DoD prime contract
   subject to DFARS Subpart 204.73.
2. That prime contract requires the prime to safeguard Covered
   Defense Information / CUI per DFARS 252.204-7012.
3. The prime intends to use the CSP's CSO to store, process, or
   transmit any of that CDI / CUI.

LOOP-S does NOT apply when:

- All customers are civilian agencies (DFARS does not apply).
- The CSP's CSO does not process any CUI / CDI (the operational
  obligations attach to the CDI scope).
- The CSP is a downstream subprocessor without a direct DFARS
  flow-down (then it inherits via DFARS 7012(m); the prime is
  responsible for ensuring the CSO is in scope).

The `--dfars-equivalency` flag is the operator's binary signal that
the gate is open. When the flag is unset, NONE of the LOOP-S risks
above activate.

---
