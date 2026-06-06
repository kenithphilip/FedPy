# LOOP-I — Stakeholder Dashboards

> **Self-contained implementation spec.** Any future session can read this file
> alone (plus `cloud-evidence/CLAUDE.md` for the REO standard) and ship every
> slice in LOOP-I without referring back to the planning conversation.
>
> **Loop ID:** I. **Slices:** I.I1, I.I2, I.I3, I.I4. **Estimated effort:** 3
> weeks single-thread. **Dependency:** LOOP-B.B1 must be complete (real risk
> scores) before I.I1 + I.I3 can render their primary visualizations.

---

## 1. Why this loop exists

The FedRAMP 20x program (RFC-0014) and the Phase Two pilot move authorization
from a written-attestation model to a continuously-validated model. Once the
authorization package ships (LOOP-A through LOOP-H), the CSP must keep
stakeholders — internal executives, the FedRAMP PMO, leveraging agencies, and
the assigned 3PAO — informed of **current posture** between submissions. The
existing artifacts (OSCAL POA&M, Integrated Inventory Workbook, signed
manifest) are authoritative but unreadable to a stakeholder who is not a
3PAO. LOOP-I closes that "last mile of trust" gap by producing four
dashboards / reports that summarize the existing real evidence:

1. **I.I1 — Executive posture dashboard.** Top-10 risks (sorted by LOOP-B.B1
   composite), overall passing-ratio %, KEV exposure count, days-until-
   next-ConMon-deliverable. Lets a CISO answer "what's our FedRAMP posture
   today?" in under 30 seconds.
2. **I.I2 — Finding burndown + deadline pipeline.** Visualizes the POA&M
   lifecycle (open → in-progress → closed) over time, grouped by severity
   and by deadline-proximity bucket. Lets a remediation lead answer "are we
   on track to close the Critical findings by their FedRAMP deadline?".
3. **I.I3 — Longitudinal trend analysis.** Per-KSI pass-rate over time +
   regression detection (alerts when a previously-passing KSI flips to
   failing). Closes the gap that the current `core/diff-report.ts`
   addresses point-in-time but not longitudinally.
4. **I.I4 — SSP narrative library completion.** Canonicalizes the auto-
   narratives the SSP emitter generates today (`core/oscal-ssp.ts`) into
   an operator-editable library, with per-control overrides. Reduces the
   manual SSP-authoring burden that LOOP-C.C* templates only partially
   address.

**Artifacts delivered (8 total):**

| Slice | Artifact path | Type |
|---|---|---|
| I.I1 | `tracker/client/src/pages/PostureDashboard.tsx` | React UI page |
| I.I1 | `cloud-evidence/out/posture-snapshot.json` | Snapshot for tracker import |
| I.I2 | `tracker/client/src/pages/FindingBurndown.tsx` | React UI page |
| I.I2 | `cloud-evidence/out/burndown-series.json` | Time-series data |
| I.I3 | `tracker/client/src/pages/TrendAnalysis.tsx` | React UI page |
| I.I3 | `cloud-evidence/out/trend-analysis.json` | Aggregated history |
| I.I3 | `cloud-evidence/out/trend-regressions-<YYYY-MM-DD>.json` | Alert payload |
| I.I4 | `cloud-evidence/out/ssp-narrative-library.json` | Canonical library |

**Authorization package gaps closed:**
- Section D of the FedRAMP 20x requirements doc (stakeholder dashboards).
- The "ongoing posture" expectation in NIST SP 800-137 §3.6 (status reporting).
- The "Trust Center"-style executive view referenced in RFC-0014 KSI ADS-CSO-PUB.
- The manual-SSP-narrative burden documented in `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`.

---

## 2. Dependencies

### Loops/slices that must complete first
- **LOOP-A.A1 (POA&M emitter).** Done. Provides `out/poam.json` schema +
  `risk` + `finding` + `poam-item` objects that I.I1 (top-10), I.I2
  (burndown), and I.I3 (trend) all read.
- **LOOP-A.A4 (submission bundler).** Done. Provides `INDEX.json` chain status
  used by I.I1 to render the "next ConMon deliverable" tile.
- **LOOP-B.B1 (CVSS+EPSS+criticality+exposure risk score).** Required for
  I.I1 + I.I3. The composite-score field at `poam-item.props[name="composite-score"]`
  is what I.I1 sorts on. If LOOP-B.B1 has not landed when I.I1 is
  implemented, I.I1 falls back to severity-only ranking and emits a
  `requires_b1_for_full_ranking` diagnostic — but does not silently
  substitute fake scores (per REO Rule 1.7).
- **LOOP-B.B3 (risk acceptance).** Soft dependency for I.I2 — when present,
  the burndown chart adds a `deviation-approved` lane; when absent, that
  lane is omitted (no synthetic data).
- **REO-0 (Real-Evidence-Only standard + 3 CI guardrails).** Done. Every
  artifact in this loop is verified by `npm run check:reo` (G1 + G2 + G3).

### Existing files this loop extends or reads from
| Path | Used by | Read or extend |
|---|---|---|
| `cloud-evidence/core/oscal-poam.ts` | I.I1, I.I2, I.I3 | read `out/poam.json` |
| `cloud-evidence/core/oscal-ssp.ts` | I.I4 | extend with narrative library hook |
| `cloud-evidence/core/findings.ts` | I.I1, I.I2 | read Finding schema |
| `cloud-evidence/core/ksi-map.ts` | I.I3, I.I4 | read KSI registry |
| `cloud-evidence/core/control-benchmark.ts` | I.I3, I.I4 | read 800-53 mapping |
| `cloud-evidence/core/run-ledger.ts` | I.I2, I.I3 | read prior-run records |
| `cloud-evidence/core/diff-report.ts` | I.I3 | reuse snapshot machinery |
| `cloud-evidence/core/inventory-coverage-report.ts` | I.I1 | reuse fill-rate calc |
| `cloud-evidence/core/csx-sum-aggregator.ts` | I.I1 | reuse passing-ratio calc |
| `cloud-evidence/core/submission-bundle.ts` | I.I1 | read `INDEX.json` chain status |
| `cloud-evidence/core/kev-feed.ts` | I.I1 | read CISA KEV catalog |
| `cloud-evidence/core/envelope.ts` | I.I1, I.I2, I.I3 | read EvidenceFile + Finding types |
| `cloud-evidence/core/orchestrator.ts` | All slices | wire `--dashboard-*` flags |
| `cloud-evidence/core/submission-bundle.ts` | All slices | extend well-known catalogue |
| `tracker/server/schema.sql` | I.I2, I.I3 | new tables for history persistence |
| `tracker/server/index.ts` | All UI slices | mount new routes |
| `tracker/client/src/lib/api.ts` | All UI slices | add fetch wrappers |
| `tracker/client/src/lib/formatting.ts` | All UI slices | reuse pills, ProgressBar |
| `tracker/client/src/pages/Dashboard.tsx` | I.I1 | add navigation link |

### Loops unblocked WHEN this loop completes
- **LOOP-E.E1 (monthly ConMon analysis report).** Uses I.I3 trend data to
  populate the "month-over-month" section of the ConMon PDF.
- **LOOP-F.F5 (3PAO recommendation letter).** Uses I.I1 posture snapshot in
  the "current state of system security" section.
- **LOOP-G.G3 (AFR-ADS Trust Center).** The publicly-shareable subset of
  I.I1 (passing-ratio %, last-attested-at) is the candidate "Trust
  Center" payload referenced by RFC-0014 ADS-CSO-PUB.
- **LOOP-G.G6 (AFR-CCM report publication + feedback mechanism).** Uses
  I.I3 + I.I2 as the monthly OAR-AVL payload + provides the "next-report
  date" tile data.

---

## 3. Authoritative sources

Quoted verbatim where possible. URLs verified 2026-06-06.

### 3.1 NIST SP 800-137 — Information Security Continuous Monitoring (ISCM)
- **URL:** https://csrc.nist.gov/pubs/sp/800/137/final
- **PDF:** https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf
- **Version:** September 2011 (current).
- **Relevant sections:**
  - §3.1 (ISCM Process) — defines the six-step ISCM lifecycle: Define
    strategy → Establish program → Implement program → Analyze findings
    → Respond → Review and update. Sections I.I1–I.I3 surface steps 3, 4,
    and 6 to humans.
  - §3.5 (Respond to findings) — "Findings are analyzed, classified, and
    prioritized for action." (paraphrased — the 800-137 PDF is binary;
    operators can confirm against the printed copy.)
  - §3.6 (Review and update) — defines the trend-analysis + program-
    effectiveness review the longitudinal dashboard (I.I3) supports.
  - Appendix D — sample metrics taxonomy distinguishing **implementation**,
    **effectiveness**, and **impact** metrics. LOOP-I I.I1 surfaces all
    three buckets: passing-ratio (implementation), KEV exposure
    (effectiveness), days-to-next-deliverable (impact).

### 3.2 FedRAMP Rev5 ConMon Playbook
- **URL:** https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/
- **Verbatim quote (verified 2026-06-06):**
  > "Each month, the CSP uploads an up-to-date POA&M and inventory, along
  > with raw vulnerability scan files (when required by agreements with
  > agency customers) and reports to the secure repository."
- **URL:** https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/
- **Verbatim quote:**
  > "FedRAMP vulnerability scanning guidelines require at least monthly
  > scans of 100% of inventory components."
- **Verbatim quote:**
  > "The scan output must display all scan findings with a low risk or
  > higher in a structured, machine-readable format (such as XML, CSV, or
  > JSON)."

### 3.3 FedRAMP RFC-0014 (Key Security Indicators)
- **URL:** https://www.fedramp.gov/rfcs/0014/
- **Verbatim quote (verified 2026-06-06):**
  > "During Phase Two, FedRAMP will expect truly automated and opinionated
  > validation of Key Security Indicators for a Moderate authorization."
- **Verbatim quote (KSI-CNA-08):**
  > "Use automated services to persistently assess the security posture of
  > all services and automatically enforce secure operations."
- **Verbatim quote (KSI-SVC-01):**
  > "Continuously evaluate machine-based information resources for
  > opportunities to improve security."
- **Verbatim quote (KSI-SVC-09):**
  > "continuously validate the authenticity and integrity of communications
  > between information resources."
- **Implication for I.I3:** The "continuously evaluate" language obligates
  longitudinal evidence; a single point-in-time snapshot does not satisfy
  KSI-SVC-01 + KSI-CNA-08 + KSI-SVC-09. I.I3 trend-analysis.json is the
  durable evidence object.

### 3.4 CISA Known Exploited Vulnerabilities (KEV) Catalog
- **URL:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Local catalog:** `cloud-evidence/docs/cisa-kev.generated.json` (already
  committed; refreshed by existing kev-feed.ts).
- **Field used by I.I1:** `vulnerabilities[].dueDate` (CISA-published 21-day
  remediation deadline per Binding Operational Directive 22-01).
- **Existing reconcile:** `providers/{aws,gcp,azure}/vdr-scan.ts` joins
  scan findings to KEV. I.I1 reads the join output to count
  KEV-exposed-and-open findings.

### 3.5 OSCAL v1.1.2 System Security Plan model
- **URL:** https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
- **Local schema:** `cloud-evidence/docs/oscal/oscal_ssp_schema.v1.1.2.json`
- **I.I4-relevant field:**
  - `control-implementation.implemented-requirements[].statements[].by-components[].description`
    — the canonical OSCAL slot for human-authored narrative prose. I.I4
    populates this from the narrative library + per-control override.
  - `control-implementation.implemented-requirements[].statements[].by-components[].set-parameters[]`
    — parameter-substitution within the narrative (e.g. session-timeout
    minutes). I.I4 surfaces these for operator editing.
  - `control-implementation.implemented-requirements[].statements[].by-components[].responsible-roles[]`
    — role-attribution. I.I4 does NOT auto-derive these (per REO Rule 4 —
    organizational role assignment is operator-supplied).

### 3.6 OSCAL POA&M v1.1.2 model
- **URL:** https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
- **Local schema:** `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json`
- **I.I2-relevant field:** `poam-items[].related-risks[].response.lifecycle` —
  enumerated string {`recommendation`, `planned`, `in-progress`, `completed`}.
  This is the canonical "lifecycle stage" I.I2 visualizes.
- **I.I1-relevant field:** `risks[].deadline` (ISO 8601 date) — drives the
  "days-until-deadline" tile.

### 3.7 GoComply/oscalkit + brian-ruf/oscal-content-generation patterns
- **URL:** https://github.com/GoComply/oscalkit
- **URL:** https://github.com/brian-ruf/oscal-content-generation
- **Observation (verified by WebFetch 2026-06-06):** The `oscal-content-
  generation` project's `ssp_content_creator.py` "automates population of
  SSP documents by creating implemented-requirement assemblies within
  existing SSPs based on FedRAMP baselines" — this is **structural
  scaffolding**, not a narrative library. I.I4 deliberately closes the
  gap GoComply leaves open: a canonical, per-control, operator-editable
  narrative library.

### 3.8 Industry GRC dashboard patterns (informative, not authoritative)
- **RegScale public docs:** https://regscale.com/docs (executive ATO
  dashboard pattern — posture % + risk register + next-report-date tile).
- **Drata public docs:** https://drata.com/product/continuous-compliance
  (continuous monitoring drift visualization pattern).
- **Vanta public docs:** https://www.vanta.com/products/automation
  (control pass/fail trend visualization pattern).
- **Workstreet KSI guide:** https://www.workstreet.com/blog/fedramp-20x-key-security-indicators
  — confirms the industry expectation that "teams will interpret live
  KSI streams and real-time posture dashboards to meet continuous
  reporting requirements" under FedRAMP 20x.
- **These are informative.** None of them are normative for FedRAMP, but
  they confirm the dashboard pattern industry-wide.

---

## 4. Per-slice implementation specs

### Slice I.I1 — Executive posture dashboard

**Why this slice:** Today there is no single screen a CISO or system owner
can open to see "what's our FedRAMP posture right now?". The signed
artifacts are authoritative but unreadable to non-3PAOs. This slice closes
that gap.

**Files to create** (exact paths):
- `cloud-evidence/core/posture-snapshot.ts` — pure builder that aggregates
  POA&M + risks + KEV + ConMon-calendar into a `PostureSnapshot` object
  and disk emitter that writes `out/posture-snapshot.json`.
- `cloud-evidence/tests/core/posture-snapshot.test.ts` — pure builder +
  emitter unit tests.
- `tracker/server/routes/posture.ts` — ingest + serve endpoint:
  `POST /api/posture/ingest` (signed-snapshot upload) + `GET /api/posture/current`.
- `tracker/server/routes/posture.test.ts` — route tests.
- `tracker/server/db/migrations/010_posture_snapshots.sql` — schema for
  history persistence.
- `tracker/client/src/pages/PostureDashboard.tsx` — React page.
- `tracker/client/src/pages/PostureDashboard.test.tsx` — component tests.

**Files to extend:**
- `cloud-evidence/core/orchestrator.ts` — add `--posture-snapshot` flag +
  `CLOUD_EVIDENCE_POSTURE_SNAPSHOT` env. Runs AFTER `--oscal-poam` because
  it depends on `out/poam.json`.
- `cloud-evidence/core/submission-bundle.ts` — add `'posture-snapshot'`
  role + `posture-snapshot.json` filename to the well-known catalogue
  with `required: false`.
- `tracker/server/index.ts` — mount `/api/posture` router.
- `tracker/client/src/lib/api.ts` — add `postureCurrent()` + `postureHistory()`.
- `tracker/client/src/App.tsx` (or main router file) — add
  `/posture` route → `PostureDashboard`.
- `tracker/client/src/pages/Dashboard.tsx` — add link tile to
  `/posture` named "Executive posture".

**Schemas / standards:**
- **OSCAL POA&M v1.1.2** (cited §3.6 above):
  - Read `out/poam.json` → `risks[]` array.
  - For each risk: read `props[name="composite-score"]` (LOOP-B.B1 emit)
    as `Number` in `[0, 100]`. If absent, fall back to severity-only with
    the mapping `critical=90, high=70, medium=50, low=30, info=10`.
  - Read `props[name="kev-due-date"]` (LOOP-B.B2 emit) for KEV deadlines.
  - Read `deadline` (ISO 8601) for the deadline tile.
- **CISA KEV** (cited §3.4 above): count of risks whose
  `props[name="kev-flag"] == "true"` AND `lifecycle ≠ "completed"`.
- **CSX-SUM passing ratio:** reuse `csx-sum-aggregator.ts` `buildCsxSum()`
  return value (`passing_count / total_count`).
- **ConMon calendar:** hard-coded FedRAMP cadence from §3.2:
  - Monthly POA&M+inventory: 1st business day of each month after the
    POA&M's `metadata.last-modified`.
  - Annual SSP review: 365 days after the SSP's `metadata.last-modified`.
  - Triennial reauthorization: 1095 days after the AR's
    `metadata.last-modified`.
- **Submission chain status:** read `out/submission-package/INDEX.json`
  `chain_status` field (LOOP-A.A4 emit).

**Build steps:**
1. **Define types** in `posture-snapshot.ts`:
   ```ts
   export interface PostureSnapshot {
     snapshot_id: string;            // deterministic UUID v5 from (system_id, generated_at)
     system_id: string;
     impact_level: 'low' | 'moderate' | 'high';
     generated_at: string;           // ISO 8601
     passing_ratio: {
       numerator: number;
       denominator: number;
       percent: number;              // numerator / denominator * 100, rounded 1 dp
       source: 'csx-sum-aggregator';
     };
     top_risks: TopRisk[];           // length ≤ 10
     kev_exposure: {
       open_count: number;
       overdue_count: number;        // KEV due_date < now AND lifecycle ≠ completed
       source: 'core/kev-feed.ts + out/poam.json';
     };
     conmon_calendar: ConmonCalendar;
     chain_status: 'complete' | 'broken' | 'absent';   // from INDEX.json
     diagnostics: string[];          // e.g. ["requires_b1_for_full_ranking"]
     provenance: {
       emitter: 'core/posture-snapshot.ts';
       emittedAt: string;
       sourceCalls: string[];        // ["read out/poam.json", "read out/submission-package/INDEX.json", ...]
       signingKeyId?: string;        // populated by core/sign.ts when --sign
     };
   }
   export interface TopRisk {
     risk_uuid: string;
     finding_uuid: string;
     title: string;                  // copied verbatim from poam-item.title
     composite_score: number;        // 0..100
     composite_score_source: 'b1-composite' | 'severity-baseline';
     severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
     deadline: string;               // ISO 8601
     days_until_deadline: number;    // negative if overdue
     kev_flagged: boolean;
   }
   export interface ConmonCalendar {
     next_poam_due: string;          // ISO date
     next_inventory_due: string;     // ISO date
     next_annual_review_due: string; // ISO date
     next_triennial_due: string;     // ISO date
     days_until_next_deliverable: number;
   }
   ```
2. **Pure builder signature:**
   ```ts
   export function buildPostureSnapshot(input: {
     poam: any;                                  // parsed out/poam.json
     csxSummary: { passing: number; total: number };
     kevCatalog: { cveId: string; dueDate: string }[];
     indexJson: any | null;                      // parsed out/submission-package/INDEX.json
     systemId: string;
     impactLevel: 'low' | 'moderate' | 'high';
     now: Date;                                  // injected for determinism
   }, opts: { topN?: number } = {}): PostureSnapshot
   ```
3. **Risk ranking algorithm:**
   - Filter `poam.risks[]` where lifecycle ≠ `completed` (status field on
     `related-observations` per OSCAL).
   - For each, read `props[name="composite-score"]`. If absent for any
     risk: set `composite_score_source = 'severity-baseline'` and push
     `'requires_b1_for_full_ranking'` into `diagnostics` (push exactly once,
     not per-risk).
   - Sort descending by `composite_score`; tie-break by earlier `deadline`,
     then by `finding_uuid` lexicographically (deterministic).
   - Slice to `topN ?? 10`.
4. **KEV exposure:** scan `poam.risks[]` for `props[name="kev-flag"] = "true"`.
   `overdue_count` = subset where `Date(props[kev-due-date]) < now AND
   lifecycle ≠ "completed"`. If POA&M has no KEV props at all (LOOP-B.B2
   not yet shipped), `open_count = 0`, `overdue_count = 0`, and push
   `'requires_b2_for_kev_overdue_calc'` to diagnostics.
5. **ConMon calendar:**
   - `next_poam_due`: 1st calendar day of the month following
     `poam.metadata.last-modified`. Skip to next business day (Mon-Fri)
     via `core/bizdays.ts` (existing).
   - `next_inventory_due`: same calc.
   - `next_annual_review_due`: `last-modified + 365d`.
   - `next_triennial_due`: read AR `last-modified` if present; if AR
     absent, omit field + push diagnostic.
   - `days_until_next_deliverable`: min across all four (days, can be
     negative).
6. **Disk emitter:**
   ```ts
   export function emitPostureSnapshot(opts: {
     outDir: string;
     outPath?: string;                            // default: outDir/posture-snapshot.json
     systemId: string;
     impactLevel: 'low' | 'moderate' | 'high';
     now?: Date;                                  // default new Date()
   }): { path: string; snapshot: PostureSnapshot }
   ```
   Reads `outDir/poam.json`, `outDir/csx-sum.json` (existing aggregator
   output), `docs/cisa-kev.generated.json`, `outDir/submission-package/
   INDEX.json` (optional), writes JSON with `provenance.sourceCalls`
   listing every read. Throws `PostureBuilderError` (typed) when
   `poam.json` is missing — never substitutes empty risks.
7. **Wire into orchestrator:**
   - New flag `--posture-snapshot` (env `CLOUD_EVIDENCE_POSTURE_SNAPSHOT`)
     placed BETWEEN `--oscal-poam` and `--sign` in the orchestrator's
     pipeline. The snapshot is then covered by the signed manifest.
   - When the orchestrator detects POA&M was not emitted in this run (no
     `out/poam.json`), it skips the snapshot AND logs
     `posture-snapshot:skipped reason=no-poam` — does NOT fail.
8. **Tracker ingest:**
   - `POST /api/posture/ingest` accepts a signed
     `posture-snapshot.json` + Ed25519 signature; verifies against the
     pinned signing key; persists to `posture_snapshots` table.
   - Schema migration `010_posture_snapshots.sql`:
     ```sql
     CREATE TABLE IF NOT EXISTS posture_snapshots (
       snapshot_id TEXT PRIMARY KEY,
       system_id TEXT NOT NULL,
       impact_level TEXT NOT NULL,
       generated_at TEXT NOT NULL,
       passing_percent REAL NOT NULL,
       kev_open_count INTEGER NOT NULL,
       kev_overdue_count INTEGER NOT NULL,
       chain_status TEXT NOT NULL,
       payload_json TEXT NOT NULL,
       signature TEXT NOT NULL,
       ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
     );
     CREATE INDEX IF NOT EXISTS idx_posture_system_time
       ON posture_snapshots(system_id, generated_at DESC);
     ```
9. **UI page `PostureDashboard.tsx`:**
   - 4 top-row tiles: `passing_ratio.percent` (with ProgressBar),
     `kev_exposure.overdue_count` (red if > 0), `chain_status` (pill:
     green=complete / amber=absent / red=broken),
     `conmon_calendar.days_until_next_deliverable` + label of which
     deliverable.
   - Top-10 risks table: title, composite_score, severity pill, deadline
     (with relative-days highlight: red if overdue, amber if < 14 days,
     green otherwise), KEV badge if `kev_flagged`.
   - Diagnostics panel: list every entry in `diagnostics[]` verbatim with
     a contextual explanation (e.g. "B1 not yet shipped — ranking uses
     severity baseline").
   - "Generated at" footer with the snapshot ID + signing key id when
     present.
   - Empty-state: when the API returns no snapshots, show "Run
     `npm run collect -- --posture-snapshot` and re-ingest. See
     RUNBOOK.md §Posture Snapshot."
10. **Add to submission-bundle.ts catalogue:**
    - role: `'posture-snapshot'`
    - filename pattern: `posture-snapshot.json`
    - required: `false`
    - description: `"Executive posture snapshot for stakeholder review (LOOP-I.I1)"`

**REQUIRES-OPERATOR-INPUT fields:**
- `system_id`: source = CLI flag `--system-id` or env `CLOUD_EVIDENCE_SYSTEM_ID`.
  Already established by LOOP-A.A2.
- `impact_level`: source = CLI flag `--impact-level` (existing).
- No new operator inputs — every other field is auto-derived from real
  artifacts. If a field cannot be auto-derived (e.g. B.B1 not shipped),
  emit a diagnostic, not a fabricated value.

**Test specifications** (12 tests):
1. `it('builds a snapshot with top-10 risks from a real POA&M', ...)` —
   fixture: 12 risks, asserts only top 10 returned, sorted by
   composite_score descending.
2. `it('falls back to severity baseline and emits diagnostic when B.B1 props absent', ...)`.
3. `it('computes passing_ratio.percent from csx-sum.json', ...)` —
   numerator/denominator round-trip.
4. `it('counts only non-completed risks for top_risks', ...)`.
5. `it('marks kev_overdue_count when KEV due_date < now', ...)` —
   inject `now`.
6. `it('emits requires_b2_for_kev_overdue_calc when no kev-flag props found', ...)`.
7. `it('computes next_poam_due as the next business day on/after the 1st of next month', ...)`.
8. `it('marks chain_status from INDEX.json when present, "absent" when missing', ...)`.
9. `it('throws PostureBuilderError when out/poam.json is missing', ...)` —
   never silent fallback.
10. `it('produces identical JSON when called twice with identical inputs', ...)`
    — determinism (key for sign-and-verify).
11. `it('emits provenance.sourceCalls listing every file read', ...)`.
12. `it('caps top_risks at the requested topN', ...)` — pass topN=3.

**Tracker route tests** (~6 tests):
1. `POST /api/posture/ingest` accepts valid signed payload, persists row.
2. Rejects payload with invalid signature (HTTP 400).
3. `GET /api/posture/current` returns most recent row for system_id.
4. `GET /api/posture/current` returns 404 when no rows.
5. Ingest is idempotent: same snapshot_id replays as 200 + no duplicate row.
6. Cross-system isolation: system A cannot read system B's snapshot.

**UI component tests** (~3 tests):
1. Renders 10 risks when API returns 10.
2. Shows "no snapshots ingested" empty state.
3. Renders diagnostic strings verbatim.

**REO compliance checks specific to this slice:**
- Every emitted value traces to: `out/poam.json` (POA&M emitter from
  LOOP-A.A1), `out/csx-sum.json` (existing aggregator),
  `docs/cisa-kev.generated.json` (committed CISA catalog), or
  `out/submission-package/INDEX.json` (LOOP-A.A4). NO synthetic values.
- Operator-input markers: NONE — all inputs are auto-derivable. When a
  field cannot be auto-derived (e.g. composite_score before B.B1 ships),
  the emitter falls back AND emits a `diagnostics[]` entry. Never
  fabricates a score.
- Signature provenance: when `--sign` is set, `provenance.signingKeyId`
  is populated by `core/sign.ts`; tests verify the snapshot is in the
  signed file list.
- `npm run check:provenance` passes because `provenance.emitter` +
  `sourceCalls` are present.

**Verification commands:**
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/posture-snapshot.test.ts
cd ../tracker
npm test -- tracker/server/routes/posture.test.ts
npm test -- tracker/client/src/pages/PostureDashboard.test.tsx
cd ../cloud-evidence
npm run check:reo
```

**Estimated effort:** 4 days (1d builder, 1d emitter+wiring, 1d tracker
ingest + DB, 1d UI + tests).

---

### Slice I.I2 — Finding burndown + deadline pipeline

**Why this slice:** A remediation lead needs to see the POA&M lifecycle
over time to plan staffing and forecast missed-deadline risk. The current
`out/poam.json` is point-in-time only; there is no longitudinal series.

**Files to create:**
- `cloud-evidence/core/burndown-series.ts` — pure builder that walks the
  run-ledger history + current POA&M to produce a time series of
  `{date, severity, lifecycle_stage, count}` rows.
- `cloud-evidence/tests/core/burndown-series.test.ts` — unit tests.
- `tracker/server/routes/burndown.ts` — endpoints:
  `POST /api/burndown/ingest`, `GET /api/burndown/series?system_id&from&to`.
- `tracker/server/routes/burndown.test.ts` — route tests.
- `tracker/server/db/migrations/011_burndown_history.sql` — append-only
  history table.
- `tracker/client/src/pages/FindingBurndown.tsx` — React page with
  stacked-area chart + deadline pipeline.
- `tracker/client/src/pages/FindingBurndown.test.tsx` — component tests.
- `tracker/client/src/lib/burndown-chart.ts` — pure SVG chart renderer
  (dependency-free; mirrors how `ssp-docx.ts` keeps the .docx renderer
  dep-free). No `recharts`, no `d3` runtime dep.

**Files to extend:**
- `cloud-evidence/core/orchestrator.ts` — add `--burndown-series` flag +
  `CLOUD_EVIDENCE_BURNDOWN_SERIES` env. Runs after `--oscal-poam`.
- `cloud-evidence/core/submission-bundle.ts` — add `'burndown-series'`
  role + `burndown-series.json` filename, `required: false`.
- `cloud-evidence/core/run-ledger.ts` — extend `RunLedger.append()` to
  also persist `{run_id, ended_at, poam_risk_count, lifecycle_breakdown}`
  so the burndown builder has historical anchors. Backward-compatible:
  old ledger entries without these fields are simply skipped.
- `tracker/client/src/lib/api.ts` — add `burndownSeries(params)` wrapper.
- `tracker/client/src/App.tsx` — add `/burndown` route.
- `tracker/server/index.ts` — mount `/api/burndown` router.

**Schemas / standards:**
- **OSCAL POA&M lifecycle** (cited §3.6 above): the lifecycle enum is the
  Y-axis grouping {`recommendation`, `planned`, `in-progress`, `completed`}.
  We add an explicit `not-tracked` bucket for findings that have no
  `response.lifecycle` set (this is a clean state, not synthetic).
- **FedRAMP severity → deadline-bucket mapping** (already encoded in
  `core/oscal-poam.ts`):
  - Critical: 30d. Bucket boundaries: ≤7d, 8-14d, 15-30d, overdue.
  - High: 60d. Bucket boundaries: ≤14d, 15-30d, 31-60d, overdue.
  - Medium: 90d. Bucket boundaries: ≤30d, 31-60d, 61-90d, overdue.
  - Low: 180d. Bucket boundaries: ≤60d, 61-120d, 121-180d, overdue.
  - Info: 365d. Bucket boundaries: ≤180d, 181-365d, overdue.
- **Run ledger format:** see existing `core/run-ledger.ts` — append-only
  JSON-Lines at `out/run-ledger.jsonl`.

**Build steps:**
1. **Define types:**
   ```ts
   export type Lifecycle = 'recommendation' | 'planned' | 'in-progress'
     | 'completed' | 'deviation-approved' | 'not-tracked';
   export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
   export interface BurndownPoint {
     date: string;                   // ISO 8601 date
     run_id: string;
     severity: Severity;
     lifecycle: Lifecycle;
     count: number;
   }
   export interface DeadlinePipelineRow {
     finding_uuid: string;
     title: string;
     severity: Severity;
     lifecycle: Lifecycle;
     deadline: string;
     days_until_deadline: number;
     deadline_bucket: '≤7d' | '8-14d' | '15-30d' | '31-60d' | '61-90d'
       | '91-180d' | '181-365d' | 'overdue' | 'no-deadline';
   }
   export interface BurndownSeries {
     series_id: string;              // deterministic UUID v5 from (system_id, range)
     system_id: string;
     range: { from: string; to: string };
     points: BurndownPoint[];
     current_pipeline: DeadlinePipelineRow[];
     diagnostics: string[];
     provenance: { emitter: 'core/burndown-series.ts'; emittedAt: string;
                   sourceCalls: string[]; signingKeyId?: string };
   }
   ```
2. **Pure builder:**
   ```ts
   export function buildBurndownSeries(input: {
     ledgerEntries: RunLedgerEntry[]; // read from out/run-ledger.jsonl
     currentPoam: any;                // parsed out/poam.json
     systemId: string;
     now: Date;
   }, opts: { from?: string; to?: string } = {}): BurndownSeries
   ```
3. **Series computation:**
   - For each ledger entry within `[from, to]`: emit one
     `BurndownPoint` per (severity × lifecycle) cell, with `count` from
     the stored lifecycle_breakdown.
   - For the current POA&M, emit a final-row set at `now.toISOString().slice(0,10)`.
   - Missing ledger entries: when there are fewer than 2 ledger entries
     in the range, the series is single-point. Push diagnostic
     `'requires_run_history_for_burndown'`.
4. **Deadline pipeline:**
   - Walk `currentPoam.risks[]` where `lifecycle ≠ "completed"`.
   - Compute `days_until_deadline = daysBetween(now, risk.deadline)`.
   - Assign `deadline_bucket` per the severity-baseline table above.
   - `'no-deadline'` only when `risk.deadline` literally absent (LOOP-A.A1
     always emits one; this is defensive).
5. **Disk emitter:**
   ```ts
   export function emitBurndownSeries(opts: {
     outDir: string;
     outPath?: string;
     systemId: string;
     from?: string;
     to?: string;
     now?: Date;
   }): { path: string; series: BurndownSeries }
   ```
6. **Wire orchestrator:** new flag emits after POA&M. The run-ledger
   extension records the lifecycle_breakdown summary at run completion
   so the next invocation has the history anchor.
7. **Tracker ingest + persistence:**
   - Migration `011_burndown_history.sql`:
     ```sql
     CREATE TABLE IF NOT EXISTS burndown_points (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       system_id TEXT NOT NULL,
       observed_at TEXT NOT NULL,
       run_id TEXT NOT NULL,
       severity TEXT NOT NULL,
       lifecycle TEXT NOT NULL,
       count INTEGER NOT NULL,
       UNIQUE(system_id, observed_at, run_id, severity, lifecycle)
     );
     CREATE INDEX IF NOT EXISTS idx_burndown_system_time
       ON burndown_points(system_id, observed_at);
     ```
   - `POST /api/burndown/ingest` accepts signed `burndown-series.json`,
     verifies signature, inserts points with `INSERT OR IGNORE` (idempotent).
   - `GET /api/burndown/series?system_id&from&to` returns the points +
     a server-computed current pipeline snapshot for the latest run.
8. **UI page:**
   - **Top half:** stacked-area chart (X = date, Y = count) with one
     band per (severity × lifecycle) combination. `burndown-chart.ts`
     renders the SVG dependency-free (build path scaffold: viewBox,
     polygons, gridlines, axis ticks).
   - **Bottom half:** "Deadline pipeline" table grouped by
     `deadline_bucket` (rows ordered: overdue → ≤7d → 8-14d → …). Each
     row: title, severity pill, deadline, days_until.
   - Range picker: defaults to last 90 days.
   - Empty state: "Less than 2 runs of history found. Burndown requires
     at least 2 historical POA&M snapshots."

**REQUIRES-OPERATOR-INPUT fields:** none. All data is auto-derived from
the run-ledger + current POA&M.

**Test specifications** (~12 tests):
1. `it('builds a series with one point per (date × severity × lifecycle)', ...)`.
2. `it('emits a single-point series + diagnostic when ledger has < 2 entries', ...)`.
3. `it('respects from/to range filtering', ...)`.
4. `it('assigns deadline_bucket correctly per FedRAMP severity table', ...)`.
5. `it('marks overdue when deadline < now', ...)`.
6. `it('skips completed risks from current_pipeline', ...)`.
7. `it('handles deviation-approved lifecycle (LOOP-B.B3 hook)', ...)`.
8. `it('is deterministic given identical inputs', ...)`.
9. `it('throws BurndownBuilderError when ledger file missing', ...)`.
10. `it('emits provenance.sourceCalls listing each ledger entry source', ...)`.
11. **Route:** `ingest is idempotent on (system_id, observed_at, run_id, severity, lifecycle)`.
12. **Route:** `range query returns rows in ascending date order`.

**UI tests** (~4):
1. SVG chart renders N bands for N (severity × lifecycle) combinations.
2. Pipeline table sorts overdue → ≤7d → … correctly.
3. Empty-state when API returns < 2 points.
4. Date-range picker propagates to API call.

**Chart renderer tests** (~3):
1. `buildSvg([])` returns a minimal valid SVG (empty plot area).
2. `buildSvg(points)` includes one polygon per band.
3. Axes have at least one tick per data point.

**REO compliance:**
- Series data traces to `out/run-ledger.jsonl` (existing) + `out/poam.json`
  (LOOP-A.A1). NO synthetic historical data.
- When history is insufficient, the system emits a diagnostic + a
  single-point series (which is a true representation, not a stub).
- Chart renderer is pure-SVG no-runtime-deps; no charting library is
  required to ship under REO Rule 1.4 (no mocked runtime libraries).

**Verification commands:**
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/burndown-series.test.ts
cd ../tracker
npm test -- tracker/server/routes/burndown.test.ts
npm test -- tracker/client/src/pages/FindingBurndown.test.tsx
cd ../cloud-evidence
npm run check:reo
```

**Estimated effort:** 5 days (2d builder + SVG chart, 1d tracker
ingest, 1d UI, 1d tests + polish).

---

### Slice I.I3 — Longitudinal trend analysis

**Why this slice:** RFC-0014 (cited §3.3) obligates "continuously evaluate"
posture. The current `diff-report.ts` is point-in-time delta only.
Longitudinal trend (e.g. "KSI-IAM-MFA has been failing for 3 months") is
not surfaced anywhere. This slice closes that gap and adds regression
alerting.

**Files to create:**
- `cloud-evidence/core/trend-analysis.ts` — pure builder + emitter for
  `out/trend-analysis.json` + `out/trend-regressions-<YYYY-MM-DD>.json`.
- `cloud-evidence/tests/core/trend-analysis.test.ts` — unit tests.
- `tracker/server/routes/trends.ts` — `POST /api/trends/ingest` +
  `GET /api/trends/per-ksi?system_id&ksi_id&from&to` +
  `GET /api/trends/regressions?system_id`.
- `tracker/server/routes/trends.test.ts` — route tests.
- `tracker/server/db/migrations/012_trend_history.sql` — per-KSI history.
- `tracker/client/src/pages/TrendAnalysis.tsx` — React page.
- `tracker/client/src/pages/TrendAnalysis.test.tsx` — component tests.

**Files to extend:**
- `cloud-evidence/core/orchestrator.ts` — add `--trend-analysis` flag +
  `CLOUD_EVIDENCE_TREND_ANALYSIS` env. Runs after `--oscal-poam` and
  reads `out/run-ledger.jsonl`.
- `cloud-evidence/core/run-ledger.ts` — extend ledger entry to record
  per-KSI pass/fail summary (`ksi_summary: { ksi_id, status: 'pass'|'fail'|
  'mixed' }[]`). The current ledger already records `evidence_files[]`;
  this extends with the KSI pass/fail roll-up.
- `cloud-evidence/core/diff-report.ts` — extract `snapshotRun()` (already
  exported) into a shared helper trend-analysis reuses.
- `cloud-evidence/core/notify.ts` — add `notifyRegression()` helper that
  reuses the existing Slack/PagerDuty driver.
- `cloud-evidence/core/submission-bundle.ts` — add `'trend-analysis'`
  role.
- `tracker/server/index.ts` — mount `/api/trends`.
- `tracker/client/src/lib/api.ts` — add `trendsPerKsi()` + `trendsRegressions()`.
- `tracker/client/src/App.tsx` — add `/trends` route.

**Schemas / standards:**
- **NIST 800-137 §3.6** (cited §3.1 above) — "Review and update" of
  the ISCM strategy. Trend analysis is the data backbone for that review.
- **OSCAL CSX-SUM aggregator** (existing): provides per-KSI pass/fail at
  a single run. This slice aggregates across runs.
- **Regression definition:** for KSI `K`, a regression occurs at run `R`
  when `status(K, R) = 'fail'` AND `status(K, R-1) = 'pass'`. (Equivalent
  for `mixed`: if a single-finding KSI flips, it regresses.)

**Build steps:**
1. **Define types:**
   ```ts
   export type KsiStatus = 'pass' | 'fail' | 'mixed' | 'not-collected';
   export interface KsiTrendPoint {
     observed_at: string;            // ISO date
     run_id: string;
     ksi_id: string;
     status: KsiStatus;
     failing_finding_uuids: string[];
   }
   export interface KsiRegression {
     ksi_id: string;
     regressed_at: string;
     from_status: 'pass';            // by definition; we only alert on pass→fail
     to_status: 'fail' | 'mixed';
     run_id_before: string;
     run_id_after: string;
     failing_finding_uuids: string[];
   }
   export interface TrendAnalysis {
     analysis_id: string;            // deterministic UUID v5
     system_id: string;
     range: { from: string; to: string };
     points: KsiTrendPoint[];
     regressions: KsiRegression[];
     per_ksi_pass_rate: { ksi_id: string; window_days: number; pass_rate: number }[];
     diagnostics: string[];
     provenance: { emitter: 'core/trend-analysis.ts'; emittedAt: string;
                   sourceCalls: string[]; signingKeyId?: string };
   }
   ```
2. **Pure builder:**
   ```ts
   export function buildTrendAnalysis(input: {
     ledgerEntries: RunLedgerEntry[];
     systemId: string;
     now: Date;
   }, opts: { from?: string; to?: string; windowDays?: number } = {}): TrendAnalysis
   ```
3. **Per-KSI series:** for each unique `ksi_id` across the ledger entries
   in range, emit one `KsiTrendPoint` per ledger entry. Use the
   `ksi_summary` field added by the ledger extension; for entries without
   it (pre-LOOP-I), set `status = 'not-collected'` and push diagnostic.
4. **Regression detection:** sliding window of size 2 over points sorted
   by `observed_at`. Emit a `KsiRegression` only when `prev.status =
   'pass'` AND `next.status ∈ {'fail', 'mixed'}`. Pass→mixed is treated
   as a regression because a previously-fully-passing KSI now has at
   least one failing finding.
5. **Per-KSI pass rate:** over `windowDays` (default 90), count
   `pass / (pass + fail + mixed)` per KSI. Exclude `not-collected`.
6. **Disk emitter:** writes `trend-analysis.json` always; writes
   `trend-regressions-<YYYY-MM-DD>.json` only when `regressions.length > 0`.
   The regression file is the alerting payload that `notifyRegression()`
   pushes.
7. **Regression notification:** when `--trend-analysis` runs with
   `--notify-regressions` AND the regression file is written, the
   orchestrator calls `notifyRegression(payload, slackUrl, pagerDutyKey)`
   via the existing notify driver.
8. **Tracker ingest:** signed `trend-analysis.json` posts to
   `/api/trends/ingest`; rows persist:
   ```sql
   CREATE TABLE IF NOT EXISTS trend_points (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     system_id TEXT NOT NULL,
     ksi_id TEXT NOT NULL,
     observed_at TEXT NOT NULL,
     run_id TEXT NOT NULL,
     status TEXT NOT NULL,
     failing_finding_uuids TEXT NOT NULL,    -- JSON array
     UNIQUE(system_id, ksi_id, run_id)
   );
   CREATE TABLE IF NOT EXISTS trend_regressions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     system_id TEXT NOT NULL,
     ksi_id TEXT NOT NULL,
     regressed_at TEXT NOT NULL,
     run_id_before TEXT NOT NULL,
     run_id_after TEXT NOT NULL,
     acknowledged_at TEXT,
     acknowledged_by INTEGER REFERENCES users(id),
     payload_json TEXT NOT NULL,
     UNIQUE(system_id, ksi_id, regressed_at)
   );
   CREATE INDEX IF NOT EXISTS idx_trend_ksi_time
     ON trend_points(system_id, ksi_id, observed_at);
   ```
9. **UI page:**
   - **Top half:** per-KSI sparkline grid (1 mini chart per KSI,
     dependency-free SVG). Hover shows the failing finding count over
     time. Click → drill into per-KSI detail view (existing
     `Indicators.tsx` route).
   - **Bottom half:** "Open regressions" table — rows ordered by
     `regressed_at DESC`. Each row has an "Acknowledge" button (RBAC:
     only `system-owner` or `assessor` role).
   - Range picker default = 90 days.
   - Empty state: "No regressions detected in the selected window."
10. **Submission-bundle catalogue entry:**
    - role: `'trend-analysis'`
    - filename pattern: `trend-analysis.json`
    - required: `false`

**REQUIRES-OPERATOR-INPUT fields:** none. Trend analysis is fully
auto-derived. Acknowledging a regression in the UI is operator action
(captured in `acknowledged_by` + audit log), not auto-derived data.

**Test specifications** (~13 tests):
1. `it('builds points for every (ksi_id, ledger entry) in range', ...)`.
2. `it('marks status not-collected for legacy ledger entries without ksi_summary', ...)`.
3. `it('detects pass→fail regression', ...)`.
4. `it('detects pass→mixed regression', ...)`.
5. `it('does NOT report fail→pass as a regression', ...)`.
6. `it('emits regressions file only when regressions[] is non-empty', ...)`.
7. `it('computes per_ksi_pass_rate excluding not-collected points', ...)`.
8. `it('is deterministic given identical ledger', ...)`.
9. `it('throws TrendBuilderError when ledger file missing', ...)`.
10. `it('emits provenance.sourceCalls listing every ledger entry sourced', ...)`.
11. `it('windowDays defaults to 90', ...)`.
12. **Route:** `ingest is idempotent on (system_id, ksi_id, run_id)`.
13. **Route:** `acknowledge requires authenticated user with role ∈ {system-owner, assessor}`.

**UI tests** (~4):
1. Renders one sparkline per KSI returned.
2. Open-regressions table acknowledges via API call.
3. Empty state.
4. Drill-through navigates to `/indicators/<ksi_id>`.

**REO compliance:**
- Trend points trace to real `run-ledger.jsonl` entries. The legacy-entry
  `not-collected` fallback is a true representation (the data was
  genuinely not collected), not synthetic.
- Regression detection uses real pass/fail transitions only — no
  threshold tuning that could be gamed.
- Acknowledgement is a real human action captured in the audit log; never
  auto-acknowledged.

**Verification commands:**
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/trend-analysis.test.ts
cd ../tracker
npm test -- tracker/server/routes/trends.test.ts
npm test -- tracker/client/src/pages/TrendAnalysis.test.tsx
cd ../cloud-evidence
npm run check:reo
```

**Estimated effort:** 5 days (2d builder + tests, 1d tracker DB +
routes, 1d UI sparklines, 1d regression notification + polish).

---

### Slice I.I4 — SSP narrative library completion

**Why this slice:** The existing `core/oscal-ssp.ts` (SSP-1) emits a
draft SSP with `REQUIRES-OPERATOR-INPUT` markers in the narrative-prose
slots (`statements[].by-components[].description`). LOOP-C.C* document
templates emit operator-facing .docx versions, but the underlying
narrative content is re-authored per system. This slice canonicalizes
the auto-narrative fragments (e.g. "MFA is enforced via AWS IAM
MFA-required policy on every IAM user; see KSI-IAM-MFA evidence") into a
library that auto-fills the SSP narrative slots while preserving the
operator-override pattern.

**Files to create:**
- `cloud-evidence/core/ssp-narrative-library.ts` — library loader +
  composer + disk emitter.
- `cloud-evidence/tests/core/ssp-narrative-library.test.ts` — unit tests.
- `cloud-evidence/docs/ssp-narrative-library.seed.json` — committed
  canonical seed (one entry per 800-53 control in the FedRAMP Moderate
  baseline). Sourced from the existing `requirement-playbooks.ts`
  text fragments (no fabrication; these are already in the codebase as
  collector documentation strings).
- `cloud-evidence/tests/fixtures/narrative-overrides.example.yaml` —
  operator-overridable narrative format example.

**Files to extend:**
- `cloud-evidence/core/oscal-ssp.ts` — replace the current
  REQUIRES-OPERATOR-INPUT marker in `statements[].by-components[].description`
  with a call to `composeNarrative(controlId, statementId, byComponentName,
  ctx)` from the library. When the library has no match AND no operator
  override, the existing REQUIRES-OPERATOR-INPUT marker is preserved
  (defensive REO).
- `cloud-evidence/core/orchestrator.ts` — add
  `--narrative-overrides <path>` flag + `CLOUD_EVIDENCE_NARRATIVE_OVERRIDES`
  env. Operator commits a YAML/JSON file with per-control overrides.
- `cloud-evidence/core/submission-bundle.ts` — add
  `'ssp-narrative-library'` role for `ssp-narrative-library.json`,
  `required: false`.
- `cloud-evidence/tests/core/oscal-ssp.test.ts` — extend with 4 new
  tests verifying the library hook + override semantics.

**Schemas / standards:**
- **OSCAL SSP v1.1.2** (cited §3.5 above):
  - `control-implementation.implemented-requirements[].statements[].
    by-components[].description` — string; holds the narrative.
  - `control-implementation.implemented-requirements[].statements[].
    by-components[].set-parameters[]` — parameter substitution
    (e.g. `{ "param-id": "ac-2_prm_1", "values": ["15 minutes"] }`).
- **800-53 Rev5 control IDs** — already in `core/control-benchmark.ts`.
  The library entries are keyed by `controlId`.
- **Component model:** SSP statements have `by-component` entries
  keyed by component UUID. The library uses a stable component-name key
  (`"this-system"` for the system itself, per `oscal-content-generation`
  convention; cited §3.7 above) plus operator-defined component names.

**Build steps:**
1. **Define schema for library entries:**
   ```ts
   export interface NarrativeEntry {
     control_id: string;             // e.g. "AC-2"
     statement_id?: string;          // e.g. "AC-2_smt.a"; null = control-level
     by_component: string;           // "this-system" | operator-defined
     template: string;               // mustache-style {{var}} placeholders
     required_vars: string[];        // e.g. ["mfa_enforcement_mechanism"]
     evidence_pointer?: string;      // e.g. "KSI-IAM-MFA"
     provenance: {
       source: 'seed' | 'operator-override' | 'auto-derived';
       authored_by?: string;
       authored_at?: string;
       sourceCalls?: string[];
     };
   }
   export interface NarrativeLibrary {
     entries: NarrativeEntry[];
     last_modified: string;
     provenance: { emitter: 'core/ssp-narrative-library.ts';
                   emittedAt: string; sourceCalls: string[] };
   }
   ```
2. **Loader:**
   ```ts
   export function loadNarrativeLibrary(opts: {
     seedPath?: string;              // default: docs/ssp-narrative-library.seed.json
     overridesPath?: string;         // operator-supplied YAML/JSON
   }): NarrativeLibrary
   ```
   - Reads the seed.
   - If `overridesPath` exists, parses (YAML via existing `yaml` dep, or
     JSON) and merges: operator override REPLACES seed for matching
     `(control_id, statement_id, by_component)`.
   - Override merging is deterministic + the merged library carries
     `provenance.source = 'operator-override'` on the affected entries.
3. **Composer:**
   ```ts
   export function composeNarrative(
     library: NarrativeLibrary,
     controlId: string,
     statementId: string | null,
     byComponent: string,
     ctx: Record<string, string>,
   ): { text: string; missing_vars: string[]; from: 'library' | 'operator-override' | 'no-match' }
   ```
   - Looks up library entry by `(controlId, statementId, byComponent)`.
   - Substitutes `{{var}}` placeholders from `ctx`.
   - When a `required_var` is missing from `ctx`: leaves the
     `{{var}}` literal in place AND lists the missing var. The
     caller (oscal-ssp.ts) renders the literal as `REQUIRES-OPERATOR-INPUT:
     {{var}}` so the operator sees the gap.
   - When no entry matches: returns `from: 'no-match'` and the caller
     emits the existing `REQUIRES-OPERATOR-INPUT` marker (defensive REO).
4. **Seed file generation:**
   - Script `scripts/extract-narrative-seed.mjs` walks
     `core/requirement-playbooks.ts` + `core/ksi-map.ts` to build the
     seed entries. The committed `docs/ssp-narrative-library.seed.json`
     is the output. CSV/JSON of every 800-53 Moderate-baseline control
     gets at least a placeholder entry whose template literally is
     `"{{operator_description_for_<control_id>}}"` so the operator sees
     EXACTLY one well-known marker to override.
5. **Disk emitter:**
   ```ts
   export function emitNarrativeLibrary(opts: {
     outDir: string;
     overridesPath?: string;
   }): { path: string; library: NarrativeLibrary }
   ```
   Writes the merged library to `out/ssp-narrative-library.json` so
   downstream consumers (LOOP-C.C* document templates) can read the
   same artifact + so the SSP audit chain shows which entries were
   operator-overridden.
6. **Hook into oscal-ssp.ts:**
   - Replace the existing hard-coded REQUIRES-OPERATOR-INPUT marker in
     `buildByComponent()` (or equivalent function) with a call to
     `composeNarrative()`. When `from === 'no-match'` OR
     `missing_vars.length > 0`, retain a REQUIRES-OPERATOR-INPUT
     marker citing the missing var.
   - The SSP test fixtures stay compatible: a system with no overrides
     produces a SSP that still has REQUIRES-OPERATOR-INPUT markers in
     the well-known positions (seed file uses
     `{{operator_description_for_<control_id>}}`).
7. **Submission-bundle catalogue entry** as above.

**REQUIRES-OPERATOR-INPUT fields:**
- Per-control narrative prose: operator supplies via the
  `narrative-overrides.yaml` file referenced by
  `--narrative-overrides`. The committed seed library exposes EVERY
  Moderate control as `{{operator_description_for_<control_id>}}` so
  the operator's first task is to provide N descriptions and any
  named variables.
- Per-component `set-parameters` values: operator supplies via
  `--ssp-set-parameter <param-id>=<value>` flag (extending existing
  `oscal-ssp.ts` options).

**Test specifications** (~14 tests):
1. `it('loads the seed library from disk', ...)`.
2. `it('returns 1 entry per Moderate-baseline 800-53 control', ...)` —
   asserts count matches `buildControlBenchmark('fedramp-mod')` length.
3. `it('merges an operator override file (YAML)', ...)`.
4. `it('merges an operator override file (JSON)', ...)`.
5. `it('marks merged entries with provenance.source = "operator-override"', ...)`.
6. `it('composes narrative by substituting {{var}} placeholders', ...)`.
7. `it('lists missing required_vars and leaves {{var}} literal in output', ...)`.
8. `it('returns from = no-match when no library entry exists', ...)`.
9. `it('hooks into oscal-ssp.ts to populate by-component description', ...)`.
10. `it('preserves REQUIRES-OPERATOR-INPUT marker when no override + no fill', ...)`.
11. `it('emits the merged library to out/ssp-narrative-library.json', ...)`.
12. `it('library is deterministic given identical seed + overrides', ...)`.
13. `it('rejects an override file whose entry lacks control_id', ...)`.
14. `it('records sourceCalls in provenance', ...)`.

**REO compliance:**
- The seed file is canonical content sourced from
  `requirement-playbooks.ts` (existing real evidence-collector
  documentation strings). Each seed entry's
  `provenance.sourceCalls` cites which playbook it was extracted from.
- For controls without a playbook entry yet, the seed uses
  `{{operator_description_for_<control_id>}}` — a well-known
  REQUIRES-OPERATOR-INPUT marker (per CLAUDE.md Rule 4: operator-
  supplied input flows through config / committed override file).
- The seed is NOT a placeholder under REO Rule 1.3 — it's a structured
  override template, identical to how `oscal-ssp.ts` already emits
  REQUIRES-OPERATOR-INPUT, just now keyed and overridable per control.
- Operator overrides flow through a committed file (per CLAUDE.md
  Rule 4), not via UI free-text that bypasses audit.

**Verification commands:**
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ssp-narrative-library.test.ts
npm test -- tests/core/oscal-ssp.test.ts   # +4 hook tests
npm run check:reo
node scripts/extract-narrative-seed.mjs --verify   # idempotency check
```

**Estimated effort:** 4 days (1d seed extraction + script, 1d
composer + loader, 1d oscal-ssp.ts hook + back-compat tests, 1d
operator-override format + docs).

---

## 5. Loop-wide acceptance criteria

When EVERY slice in this loop is complete, ALL of the following must hold:

1. `cd cloud-evidence && npm run typecheck` — clean.
2. `cd cloud-evidence && npm test` — all tests passing (delta:
   +12 (I.I1) + ~19 (I.I2 including chart) + ~17 (I.I3) + ~14 (I.I4)
   = ~62 new tests).
3. `cd cloud-evidence && npm run check:reo` — G1 + G2 + G3 green.
4. `cd tracker && npm test` — tracker server + client tests green.
5. A full orchestrator run with `--posture-snapshot --burndown-series
   --trend-analysis --narrative-overrides /path/to/overrides.yaml`
   produces:
   - `out/posture-snapshot.json` (signed)
   - `out/burndown-series.json` (signed)
   - `out/trend-analysis.json` (signed)
   - `out/ssp-narrative-library.json` (signed)
   - `out/trend-regressions-<YYYY-MM-DD>.json` (only if regressions detected)
   - The new files appear in `submission-package/INDEX.json` with their
     well-known roles.
6. The tracker UI exposes 3 new pages: `/posture`, `/burndown`, `/trends`.
   Each renders against a fresh ingest with no console errors.
7. Each new artifact is reproducible: two runs with identical inputs +
   `--mtime <fixed>` produce byte-identical JSON.
8. The SSP emitter, run after I.I4 lands, populates control-implementation
   `by-components[].description` from the library (when overrides
   provided) and falls back to the REQUIRES-OPERATOR-INPUT marker
   (when not) — backwards-compatible with the existing SSP test
   fixtures.
9. CHANGELOG.md Unreleased section has 4 new entries (one per slice)
   each citing the module names + new file paths + verification counts.
10. `cloud-evidence/docs/STATUS.md` (if present) shows all 4 LOOP-I
    slices as `done`. If `STATUS.md` does not exist, create it as part
    of I.I1 with the LOOP-I and existing-LOOP status table.

---

## 6. Open questions / caveats

1. **LOOP-B.B1 ordering.** If a session starts LOOP-I before LOOP-B.B1
   completes, I.I1 ships with the severity-baseline ranking + diagnostic.
   This is acceptable per REO Rule 4 (never fabricate). When B.B1 lands
   later, a re-run of `--posture-snapshot` picks up the composite scores
   automatically with no LOOP-I code change required.

2. **LOOP-B.B3 ordering.** I.I2 burndown chart includes a
   `deviation-approved` lane only when B.B3 is shipped + the POA&M
   emitter populates that lifecycle status. If B.B3 is not yet
   shipped, the lane is silently omitted (no synthetic data) — the
   chart and pipeline still render correctly with the other 4
   lifecycle stages.

3. **Charting library decision.** The plan uses dependency-free SVG (no
   recharts / d3 runtime dep) to mirror the dependency-free .docx
   pattern in `ssp-docx.ts` + `roe-emit.ts`. If the implementer
   evaluates a runtime dep later, it MUST go through REO Rule 1.4 review
   and be pinned in `package.json` exact-version.

4. **Run-ledger backward compatibility.** Extending `RunLedger` with
   `ksi_summary` and `lifecycle_breakdown` MUST be additive: old ledger
   entries without those fields are read as `'not-collected'`. Slice
   I.I3 tests verify this explicitly.

5. **Trust Center vs internal dashboards.** LOOP-G.G3 (AFR-ADS Trust
   Center) will need a publicly-shareable subset of I.I1 — likely just
   `passing_ratio.percent` + `chain_status` + `system_id` +
   `last_attested_at`. LOOP-G.G3 implementer should add a
   `--posture-snapshot-public` flag that emits the redacted subset; this
   is NOT a LOOP-I responsibility but the JSON shape is intentionally
   compatible.

6. **Regression notification false positives.** A single-finding KSI
   that flips on a transient SDK error would trigger a regression
   alert. Mitigation: the existing `core/retry.ts` retry-with-backoff
   already filters transient errors before they reach findings. If
   field experience shows residual false positives, a future slice can
   add a 2-of-3 confirmation rule. Documented here so the implementer
   can decide whether to ship the basic rule or the confirmation rule.

7. **Narrative library i18n.** The seed library is English-only. If a
   future agency requires Spanish or other languages, the library
   schema supports it via a `locale` field (not implemented in I.I4 —
   tracked as a follow-up).

8. **OSCAL set-parameters propagation.** I.I4 wires narrative prose;
   wiring the parameter VALUES into the SSP's `set-parameters[]` array
   is a separate concern handled by the existing `oscal-ssp.ts`
   parameter-flag system. This slice does not re-implement that.

---

## 7. Status tracking

| Slice ID | Status | Commit hash | Completed date |
|---|---|---|---|
| I.I1 | pending | — | — |
| I.I2 | pending | — | — |
| I.I3 | pending | — | — |
| I.I4 | pending | — | — |

> When a slice ships, update the row in place per the procedure in §8.

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST:

1. **Verify:**
   ```bash
   cd cloud-evidence
   npm run typecheck && npm test && npm run check:reo
   cd ../tracker
   npm test
   ```
   All four commands must exit 0.

2. **Update §7 status table** in this file:
   - Set `Status` from `pending` to `done`.
   - Set `Commit hash` to the short hash of the merge/squash commit.
   - Set `Completed date` to the ISO 8601 date (YYYY-MM-DD) of the
     commit, NOT the date of the PR review.

3. **Append a CHANGELOG.md "Unreleased" entry** naming:
   - The slice ID + title (e.g. `LOOP-I.I1: Executive posture dashboard`).
   - Every new file path under `core/`, `tests/`, `tracker/server/`,
     `tracker/client/`.
   - The verification counts (test delta, REO check status).
   - The real evidence flow path (e.g. `out/poam.json` → builder →
     `out/posture-snapshot.json` → tracker ingest → DB → UI).

4. **Update `cloud-evidence/docs/STATUS.md`** to mark the slice `done`
   (if STATUS.md exists; if not, create on first slice completion).

5. **Commit** with message:
   ```
   LOOP-I.<slice-id>: <title>
   ```
   Example: `LOOP-I.I1: Executive posture dashboard`.
   Use the heredoc commit pattern documented in the repo root CLAUDE.md
   to preserve formatting.

6. **Push** to `origin/main` (or open a PR if branch protection requires;
   the loop process tracks origin/main as the published baseline for the
   coverage-regression check G2).

After step 6, the loop status snapshot in `docs/EXECUTION-PLAN.md`
should be updated to reflect the slice as complete. The next slice
in priority order (per §6 of EXECUTION-PLAN.md) becomes the next
candidate for a fresh session.
