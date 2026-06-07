---
slice_id: P.P1
title: Insider Threat Program documentation + tracker workflow
loop: P
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A4, LOOP-A.A5]
blocks: [P.P5, C.C7, E.E1]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# P.P1 — Insider Threat Program documentation + tracker workflow

## TL;DR
Ship a NIST 800-53 Rev5 PM-12 / EO 13587 / NITTF Minimum Standards Insider
Threat Program (ITP) plan emitter (`core/insider-threat-program.ts`) plus
four tracker tables (`insider_threat_program`, `insider_threat_team_roster`,
`insider_threat_indicators`, `insider_threat_cases`) + Express routes +
React UI. Emits `out/insider-threat-program.docx` and the new
`out/KSI-PIY-ITP.json` envelope that the OSCAL SSP renderer consumes for
the PM-12 implementation statement. P.P1 is the foundation slice that
defines the org-level ITP that P.P5 (monitoring) makes operational.

## Status
- Status: pending
- Commit: — (filled when shipped per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
LOOP-P.P1 reuses the existing FedPy emission rails: the OOXML `.docx`
emitter pattern from `core/roe-emit.ts` (LOOP-A.A5) + `core/ssp-2.ts`; the
KSI-envelope pattern from `core/envelope.ts`; the tracker auth + RBAC +
signed audit log pipeline. It introduces a new KSI token `PIY-ITP` mapped
to NIST 800-53 PM-12 (registered in `core/ksi-map.ts`), and a new role in
`core/submission-bundle.ts:WELL_KNOWN` (`insider-threat-program-docx` +
`insider-threat-program-snapshot`). The .docx ITP plan becomes a first-
class submission-bundle artifact a 3PAO + AO + FedRAMP PMO consume; the
JSON snapshot drives the SSP PM-12 implementation statement narrative.
No cloud SDK call is added — workforce data is process-artifact, managed
by the tracker, with cross-references to `providers/*/iam.ts` deferred to
P.P5 (where IAM-SUS correlation against ITP indicators happens).

## Why this slice exists
NIST SP 800-53 Rev5 PM-12 ("Implement an insider threat program that
includes a cross-discipline insider threat incident handling team") is in
the FedRAMP Moderate baseline. EO 13587 §2.1 binds executive-branch
agencies to "implement an insider threat detection and prevention program
consistent with guidance and standards developed by the Insider Threat
Task Force". The NITTF Minimum Standards (Nov 21, 2012) enumerate six
required program elements: ITSO designation; cross-discipline incident
handling team; access controls + monitoring; information integration +
analysis; insider-threat training; and self-assessment. 32 CFR 117.7
extends an analogous obligation to NISPOM-scoped contractors. Today the
FedPy artifact corpus has no ITP plan, no team roster, no case log, no
indicator catalogue — meaning the SSP cannot truthfully cite PM-12
implementation, and any 3PAO review of the package will surface PM-12 as
unsatisfied. P.P1 ships the .docx ITP plan + the four tracker tables that
produce signed, ongoing evidence the plan is operating.

## Authoritative sources (with verbatim quotes)

- **NIST SP 800-53 Rev5 — PM-12 (Insider Threat Program)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  Control statement (verbatim):
  > "Implement an insider threat program that includes a cross-discipline
  > insider threat incident handling team."

  Discussion text (verbatim):
  > "Organizations that handle classified information are required, under
  > Executive Order 13587 and the National Insider Threat Policy, to
  > establish insider threat programs. The standards and guidelines that
  > apply to insider threat programs in classified environments can also
  > be employed effectively to improve the security of [Controlled
  > Unclassified Information] in non-national security systems."

- **Executive Order 13587 (Oct 7, 2011)** —
  https://obamawhitehouse.archives.gov/the-press-office/2011/10/07/executive-order-13587-structural-reforms-improve-security-classified-net
  Section 2.1 / §6 (verbatim, via WebFetch 2026-06-07):
  > "Agency heads must designate a senior official and 'implement an
  > insider threat detection and prevention program consistent with
  > guidance and standards developed by the Insider Threat Task Force.'"

  > "Key duties included developing 'a Government-wide policy for the
  > deterrence, detection, and mitigation of insider threats' and issuing
  > 'minimum standards and guidance for implementation' that would be
  > 'binding on the executive branch.'"

- **NITTF — National Insider Threat Policy and Minimum Standards (Nov 21,
  2012)** —
  https://www.dni.gov/index.php/ncsc-newsroom/ncsc-cpd/3251-natinal-insider-threat-policy-and-minimum-standards
  Six required elements (paraphrased from NITTF summary; verbatim
  citation requires manual PDF download into
  `cloud-evidence/docs/sources/nittf-minimum-standards.pdf`):
  1. Designated senior official (Insider Threat Senior Official, ITSO).
  2. Cross-discipline incident handling team.
  3. Personnel access controls + monitoring of user activity on
     classified/CUI systems.
  4. Information integration + analysis.
  5. Insider threat training + awareness for all cleared personnel.
  6. Self-assessment / annual program review.

- **32 CFR 117.7 — NISPOM Insider Threat Program** —
  https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-117/section-117.7
  Verbatim (audit doc §2 LOOP-P):
  > "Contractors shall establish and maintain an insider threat program
  > to detect, deter, and mitigate insider threats."

  Requires designation of an Insider Threat Program Senior Official
  (ITPSO), capabilities to gather and integrate relevant information
  consistent with applicable law, insider-threat training within 30 days
  of initial assignment, and self-certification.

- **OSCAL SSP — `implemented-requirements`** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  Schema field set for `implementation-statement.description` (the prose
  block P.P1 populates from tracker text) and `props[]` (where the
  attestation UUID is recorded).

- **CISA Insider Threat Mitigation Guide (2023, 508 PDF)** —
  https://www.cisa.gov/sites/default/files/2023-02/Insider%20Threat%20Mitigation%20Guide_Final_508.pdf
  Used by P.P1 only for the *indicator catalogue seed* (the body of the
  table the .docx renders in §9). The detection rules consuming the
  catalogue live in P.P5.

## Files to create (exact paths under cloud-evidence/)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/insider-threat-program.ts`
  — .docx emitter (OOXML + zip-store pattern, no external libs) producing
  the ITP plan per NITTF Minimum Standards (six elements). ~700 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/itp-evidence.ts`
  — KSI envelope builder. Reads tracker tables via `core/tracker-pull.ts`;
  emits `out/KSI-PIY-ITP.json` with provenance block.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/workforce-policy.ts`
  — typed YAML loader for `config/workforce-policy.yaml` (introduced by
  P.P1 so later slices share the schema). Schema: `itp_review_cadence_days`,
  `itp_training_cadence_days`, `applies_nispom` boolean, etc.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/workforce-policy.example.yaml`
  — committed example (operator copies to `config/workforce-policy.yaml`,
  gitignored).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/insider-threat-program.ts`
  — Express CRUD routes for `insider_threat_program` +
  `insider_threat_team_roster` + `insider_threat_indicators`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/insider-threat-cases.ts`
  — Express routes scoped to case lifecycle.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/InsiderThreatProgram.tsx`
  — ITP plan editor (6 NITTF elements) + roster + cases UI.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/InsiderThreatCaseDetail.tsx`
  — per-case detail with signed audit record.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/insider-threat-program.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/itp-evidence.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/workforce-policy.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/insider-threat-program.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/insider-threat-cases.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/InsiderThreatProgram.test.tsx`

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` —
  register `PIY-ITP` token entry with NIST PM-12 mapping.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  new `--insider-threat-program` flag + env `CLOUD_EVIDENCE_ITP`; runs
  BEFORE `--oscal-ssp`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` —
  implementation statement block for PM-12 reads the ITP attestation
  + populates `implementation-statement.description` with templated
  narrative + adds prop `itp-attestation-uuid`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add roles `insider-threat-program-docx` (filename
  `insider-threat-program.docx`) and `insider-threat-program-snapshot`
  (filename `.itp-snapshot.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/envelope.ts` — no
  schema change (PIY-ITP uses standard envelope shape).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — four
  new tables (DDL in Build Steps §2).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount
  routes with `requireRole(['iso','ao','hr'])`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts` — add `hr`
  role + per-route permissions.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add
  `/insider-threat-program` and `/insider-threat-cases/:uuid` routes.

## Schemas / standards

- **NIST 800-53 Rev5 PM-12** — control statement verbatim (above).
- **EO 13587 §2.1 + §6** — agency-side ITP designation obligation.
- **NITTF Minimum Standards** — six required elements (operator attests
  each via the tracker UI; six-elements JSON canonical-signed).
- **32 CFR 117.7** — applies conditionally when `applies_nispom = true`.
- **OSCAL SSP `implemented-requirements`** — JSON-schema URL:
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  Required fields: `control-id` (PM-12), `statements[]`, optional
  `props[]` carrying our `itp-attestation-uuid` extension namespaced
  `CE_NS = "https://cloud-evidence.example/oscal-ns"`.
- **.docx OOXML** — same minimal-OOXML-zip-store pattern as
  `core/roe-emit.ts`; no external dependencies. Sections enumerated in
  Build Steps §3.

## Build steps (concrete, numbered)

1. **Define types** in `core/insider-threat-program.ts`:
   ```ts
   export interface ItpAttestation {
     uuid: string;
     itso_user_id: number;          // Insider Threat Senior Official
     itso_name: string;
     itso_title: string;
     itpso_user_id?: number;        // ITPSO (NISPOM 32 CFR 117.7 senior official)
     itpso_name?: string;
     reviewed_at: string;           // ISO datetime, signed
     review_cadence_days: number;   // operator-defined, default 365
     six_elements: {
       senior_official: { attested: boolean; user_id?: number; note?: string };
       cross_discipline_team: { attested: boolean; roster_count: number; note?: string };
       access_controls_monitoring: { attested: boolean; tool_refs: string[] };
       information_integration: { attested: boolean; analyst_user_ids: number[] };
       training: { attested: boolean; training_cadence_days: number; last_completion_pct: number };
       self_assessment: { attested: boolean; last_assessment_date: string; next_due: string };
     };
     applies_nispom: boolean;       // operator declares whether 32 CFR 117 in scope
     signature: string;             // Ed25519 over canonical JSON
     signing_key_id: string;
     created_at: string;
   }
   ```

2. **Tracker schema** (DDL, additive `CREATE TABLE IF NOT EXISTS`):
   ```sql
   CREATE TABLE IF NOT EXISTS insider_threat_program (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     itso_user_id INTEGER NOT NULL REFERENCES users(id),
     itpso_user_id INTEGER REFERENCES users(id),
     reviewed_at TEXT NOT NULL,
     review_cadence_days INTEGER NOT NULL DEFAULT 365,
     six_elements_json TEXT NOT NULL,        -- canonical JSON of attestation
     applies_nispom INTEGER NOT NULL DEFAULT 0,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     created_at TEXT NOT NULL,
     CHECK (json_valid(six_elements_json))
   );

   CREATE TABLE IF NOT EXISTS insider_threat_team_roster (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     user_id INTEGER NOT NULL REFERENCES users(id),
     discipline TEXT NOT NULL CHECK (discipline IN ('hr','security','it','legal','counterintelligence','behavioral-science','other')),
     role TEXT NOT NULL,
     joined_at TEXT NOT NULL,
     left_at TEXT,
     status TEXT NOT NULL CHECK (status IN ('active','departed'))
   );

   CREATE TABLE IF NOT EXISTS insider_threat_indicators (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     code TEXT NOT NULL UNIQUE,              -- e.g. 'CISA-CYBER-04'
     category TEXT NOT NULL CHECK (category IN ('verbal','behavioral','cyber','physical-access')),
     description TEXT NOT NULL,
     severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
     source TEXT NOT NULL                    -- e.g. 'CISA-Insider-Threat-Mitigation-Guide-2023'
   );

   CREATE TABLE IF NOT EXISTS insider_threat_cases (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     opened_at TEXT NOT NULL,
     opened_by_user_id INTEGER NOT NULL REFERENCES users(id),
     subject_user_ref TEXT NOT NULL,         -- opaque ref; NOT a user_id, to keep HR data outside ordinary RBAC
     indicators_json TEXT NOT NULL,          -- array of indicator codes
     status TEXT NOT NULL CHECK (status IN ('open','investigating','closed-substantiated','closed-unsubstantiated','referred')),
     closed_at TEXT,
     resolution_summary TEXT,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   ```

3. **.docx emitter** — sections (mirror the NITTF Minimum Standards):
   1. Cover page (system id, CSP, run id, review date, ITSO name + title)
   2. Authority + Scope (PM-12, EO 13587, NITTF Minimum Standards,
      conditionally 32 CFR 117.7 when `applies_nispom=true`)
   3. Senior Official Designation (ITSO + optional ITPSO)
   4. Cross-Discipline Team Roster (table from `insider_threat_team_roster`)
   5. Access Controls + Monitoring (references LOOP-P.P5 + existing IAM-SUS)
   6. Information Integration + Analysis (process narrative)
   7. Insider Threat Training (cadence + last completion %)
   8. Self-Assessment / Annual Program Review (last + next dates)
   9. Behavioral Indicator Catalogue (table from `insider_threat_indicators`)
   10. Case Handling Procedure (steps; signatures)
   11. Provenance (tool name, run id, ksi-map entry, NIST cite)
   - Every operator-supplied field renders `REQUIRES-OPERATOR-INPUT` when
     missing (mirroring `core/roe-emit.ts` patterns).

4. **KSI envelope builder** (`core/itp-evidence.ts`):
   - Reads tracker tables via `core/tracker-pull.ts` (existing).
   - Builds `Finding[]` entries per six-element compliance state.
   - Provenance block lists tracker URL, snapshot ISO timestamp, signing
     key id, NIST citation.
   - Emits to `out/KSI-PIY-ITP.json` with the standard envelope shape.

5. **Orchestrator wiring**: `--insider-threat-program` runs BEFORE
   `--oscal-ssp` so the SSP picks up the ITP attestation in its PM-12
   implementation statement. Documented order: collect → workforce-policy
   load → insider-threat-program emit → oscal-ssp → bundle → sign.

6. **SSP integration** (`core/oscal-ssp.ts`): when PM-12 implementation
   block is rendered, read the latest ITP attestation; populate
   `implementation-statement.description` with templated narrative citing
   the six elements + the signed attestation UUID; add prop
   `itp-attestation-uuid` namespaced `CE_NS`.

7. **Bundler integration** (`core/submission-bundle.ts`): add
   `insider-threat-program-docx` role (filename
   `insider-threat-program.docx`) and `insider-threat-program-snapshot`
   role (filename `.itp-snapshot.json` — the JSON snapshot pulled from
   tracker).

8. **Tracker RBAC** (`tracker/server/rbac.ts`):
   - Add `hr` role.
   - Per-route mapping: `POST /api/itp` requires `iso` or `ao`;
     `GET /api/itp` allows `iso|ao|assessor|hr`; case CRUD requires
     `iso`.

9. **Tracker UI** (`tracker/client/src/pages/InsiderThreatProgram.tsx`):
   - Six-element form (one accordion per element).
   - Roster table with add/remove.
   - Indicator catalogue table (seeded from CISA Mitigation Guide).
   - Case-list table with open/close actions.
   - Sign-and-submit button calls `POST /api/itp` with canonical JSON +
     server adds Ed25519 signature.

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4 (`cloud-evidence/CLAUDE.md`):

| Field | Source | Behavior when missing |
|---|---|---|
| `itso_user_id` | Operator selects from tracker user list in UI | SSP renders `REQUIRES-OPERATOR-INPUT` in PM-12 implementation statement; .docx §3 renders the marker |
| `itpso_user_id` (when `applies_nispom=true`) | Operator selects from tracker user list | Section 11 of .docx renders the marker; KSI-PIY-ITP envelope status=fail until set |
| Six-element narrative text for elements 3, 4, 6 | Operator authors prose via UI | Section renders REQUIRES-OPERATOR-INPUT inline |
| Behavioral-indicator catalogue rows | Seeded from CISA Insider Threat Mitigation Guide; operator tunes severity bands | Section 9 renders catalogue with `severity=REQUIRES-OPERATOR-INPUT` per row if untuned |
| `training.training_cadence_days` + `training.last_completion_pct` | Operator records training stats via UI | Section 7 renders marker; KSI envelope flags `training` element non-attested |
| `self_assessment.last_assessment_date` + `next_due` | Operator records via UI | Section 8 renders markers |
| `applies_nispom` | Operator declares via UI checkbox + workforce-policy.yaml fallback | Defaults to `false`; NISPOM sections render markers conditionally |
| `workforce-policy.yaml` review/training cadence overrides | `config/workforce-policy.yaml` (CLI `--workforce-policy <path>`) | Defaults from `workforce-policy.example.yaml`; documented |

## Test specifications

1. `it('emits a .docx with all 11 sections rendered')` — read the
   generated OOXML, parse the document.xml, assert each section heading.
2. `it('renders REQUIRES-OPERATOR-INPUT when ITSO unset')` — assert the
   literal marker appears in §3.
3. `it('renders ITSO name + title verbatim when set')` — round-trip a
   fixture attestation through emitter.
4. `it('renders cross-discipline team table from roster rows')` — load
   N=4 roster rows, assert N rows in the rendered table.
5. `it('renders behavioral indicator catalogue table from indicators')` —
   load N=10 indicator rows, assert table cell count.
6. `it('marks NISPOM-scope §11 REQUIRES-OPERATOR-INPUT when applies_nispom=false')`.
7. `it('signs the ITP attestation with Ed25519 over canonical JSON')` —
   verify signature using `core/sign.ts` verify path.
8. `it('KSI-PIY-ITP envelope has provenance.emitter set')`.
9. `it('KSI-PIY-ITP envelope contains a Finding per six-element state')` —
   ≥6 Findings.
10. `it('KSI-PIY-ITP envelope status reflects all-six-elements-attested')` —
    when all 6 attested, `status="pass"`; one unattested → `status="fail"`.
11. `it('tracker POST /api/itp accepts iso or ao roles only')`.
12. `it('tracker GET /api/itp returns the latest attestation')`.
13. `it('case CRUD enforces uuid stability across updates')`.
14. `it('SSP PM-12 implementation statement includes attestation UUID prop')`.
15. `it('workforce-policy.yaml loader validates schema and rejects unknown keys')`.
16. `it('UI: InsiderThreatProgram page renders six-element form correctly')`.

## REO compliance specific to this slice

- Every emitted field traces to a signed tracker row OR to operator
  config (`workforce-policy.yaml`).
- No synthesised attestation; missing fields emit REQUIRES-OPERATOR-INPUT
  visibly in the .docx + the envelope + the SSP implementation statement.
- Signatures are real Ed25519 over canonical JSON
  (`@noble/ed25519` + `rfc8785` canonicalize); no fake crypto.
- Provenance block populated on `out/KSI-PIY-ITP.json` (emitter name,
  emittedAt, sourceCalls listing tracker URL + snapshot timestamp,
  signingKeyId).
- Signed by existing `core/sign.ts` pipeline (Ed25519 + RFC 3161
  timestamp) — both the .docx and the JSON envelope land in the manifest.
- No `process.env.NODE_ENV === 'test'` branches.
- No hardcoded "all six elements attested" defaults.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/insider-threat-program.test.ts tests/core/itp-evidence.test.ts tests/core/workforce-policy.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/insider-threat-program.test.ts server/routes/insider-threat-cases.test.ts client/src/pages/InsiderThreatProgram.test.tsx
```

## Known risks / issues

- **Risk 1: NITTF Minimum Standards PDF returns 403 to anonymous fetch.**
  The dni.gov page redirects through a session-validation step. Mitigation:
  Operator downloads the PDF manually into
  `cloud-evidence/docs/sources/nittf-minimum-standards.pdf`; .docx §2
  cites the local-path + the dni.gov URL; a `REQUIRES-OPERATOR-INPUT:
  confirm-against-nittf-pdf` marker remains until the operator confirms
  via tracker UI.
- **Risk 2: 32 CFR 117 NISPOM may not apply to a given CSP.** Mitigation:
  `applies_nispom` is operator-declared; defaults `false`; when `false`
  the .docx renders NISPOM-only sections as REQUIRES-OPERATOR-INPUT but
  the PM-12 implementation statement still ships under NIST PM-12 alone.
- **Risk 3: Subject identifier exposure in case table.** Insider-threat
  investigations handle pre-adverse-action data; raw user_ids in the
  case table would leak identity to anyone with `iso` role access.
  Mitigation: `subject_user_ref` is an opaque token; the
  resolver `token→identity` lives only in a separate `case_subject_index`
  table accessible to AO only (deferred to P.P5 final schema).
- **Risk 4: ITSO designation is a single point of failure.** If the
  ITSO leaves the org, attestations become stale. Mitigation: tracker
  emits a notification 30 days before `review_cadence_days` expires;
  enforcer flags the attestation `requires-resign`.
- **Risk 5: Cross-discipline team roster could be incomplete.**
  NITTF requires HR + security + IT + legal at minimum; an attestation
  of `cross_discipline_team` should fail validation when fewer than 4
  active disciplines are represented. Mitigation: server-side validator
  rejects with HTTP 422 if `active_disciplines.size < 4`; UI surfaces.
- **Risk 6: KSI-PIY-ITP envelope status semantics.** "All six elements
  attested" does not imply "operating effectively". 3PAO inspection is
  still required. Mitigation: envelope carries `attested` semantics in
  prop description; SSP narrative does not claim operational effectiveness;
  documented in CHANGELOG.

## Open questions

- **Q1**: Should `subject_user_ref` be an opaque hash of the user_id +
  case_uuid, or a UUID minted at case-open? Hash provides verifiability
  across cases; UUID provides better privacy. Recommendation: UUID minted
  at case-open; resolver table is separate and AO-only.
- **Q2**: Should the .docx ship with the indicator catalogue table
  empty (forcing operator to populate) or pre-seeded from CISA Mitigation
  Guide? Recommendation: pre-seeded read-only baseline, with operator
  ability to add organisation-specific indicators above the baseline.
- **Q3**: What's the right cadence for ITP review when EO 13587 says
  "consistent with NITTF" but NITTF specifies "at least annually" with
  agency tunability? Recommendation: default 365 days; operator can
  shorten via `workforce-policy.yaml: itp_review_cadence_days`.

## Implementation log

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist

- [ ] typecheck clean (`npm run typecheck` in both `cloud-evidence/` + `tracker/`)
- [ ] tests passing 100% (≥16 new tests this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (P.P1 slice row + Overall section)
- [ ] LOOP-P-SPEC.md §8 status table updated (P.P1 row)
- [ ] This file's frontmatter updated (status=done, commit, completed_date)
- [ ] CHANGELOG.md "Unreleased" entry added (cites PM-12 + EO 13587 + NITTF)
- [ ] Commit with `LOOP-P.P1:` slice ID in message
- [ ] Commit amended hash recorded in STATUS.md + this file + LOOP-P-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read this file (P.P1.md) — full slice spec.
3. Read `cloud-evidence/docs/loops/LOOP-P-SPEC.md` §1, §2, §4 for loop
   context + authoritative sources.
4. Read `cloud-evidence/docs/loops/LOOP-P-RISKS.md` — live risks register.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` — mandatory
   7-step ship procedure.
6. Read `cloud-evidence/core/roe-emit.ts` — the OOXML .docx pattern to
   mirror (LOOP-A.A5).
7. Read `cloud-evidence/core/envelope.ts` — Finding interface used by
   the KSI envelope builder.
8. Read `tracker/server/rbac.ts` — current role definitions; add `hr`.
9. Begin implementation; update Implementation log section at every
   meaningful milestone (per `docs/IMPLEMENTATION-LOG-TEMPLATE.md`).
