# LOOP-G — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with status=resolved + resolution note + commit ref.
> Last updated: 2026-06-07 (planning pass — all G.G* slices still pending).
> Owner: the session implementing the slice; cross-cutting risks owned by whoever closes the loop.

---

## Cross-cutting risks (apply to ALL slices in this loop)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| LOOP-G-X1 | **FRMR `documentation.json` v0.9.43-beta is a beta release.** A v1.0 release could renumber FRMR ids or revise MUST text, invalidating the verbatim `provenance.requirementTexts` blocks we ship. | high | Treat `provenance.requirementTexts` as data: any FRMR id change is caught by a CI guardrail (`scripts/check-frmr-pin.mjs` — proposed for L-1 add) that fails the build if the live FRMR vs `frmr-requirements.generated.json` snapshot diverges. Loop-wide regression suite re-runs against the new FRMR before re-publishing. | open |
| LOOP-G-X2 | **OOXML `.docx` zip-store determinism across Node versions.** Different Node major versions sort `Object.entries()` deterministically (since 12+) but ZIP local-file-header timestamps default to "now"; we already pin them to `0x21080000` (1981-01-01) but a refactor could regress. | med | Every `.docx` emitter test asserts byte-stability across two consecutive calls; CI runs on Node 18 + 20 + 22 to catch differences. | open |
| LOOP-G-X3 | **Dependency-free `.docx` rendering quirks in Word + LibreOffice + Google Docs.** Hand-rolled OOXML is conservative but some advanced features (numbered lists with custom levels, mixed-language text) render slightly differently across clients. | med | Use only `core/ssp-docx.ts` + `core/roe-emit.ts` proven feature subset (headings 1-3, paragraph, table, page break). Avoid: custom numbering, footnotes, comments. | open |
| LOOP-G-X4 | **Tracker DB schema migrations are additive only.** A future slice may need a destructive ALTER (e.g. NOT NULL on an existing column) that breaks live tracker installs. | med | All LOOP-G migrations use `CREATE TABLE IF NOT EXISTS` + new column additions only. Operator runbook covers backup-before-upgrade per D.5 backup/restore. | open |
| LOOP-G-X5 | **Provenance block size growth.** Embedding 4-8 verbatim FRMR statements per artifact + sourceCalls + requirementTexts could bloat JSON files. | low | Cap `provenance.requirementTexts` to the slice-specific MUSTs (4-8 keys); compress only when bundled (tarball does this). | open |
| LOOP-G-X6 | **REQUIRES-OPERATOR-INPUT marker text drift.** Each slice ships a marker string; if they diverge ("REQUIRES-OPERATOR-INPUT", "REQUIRES_OPERATOR_INPUT", "[OPERATOR INPUT]") consumers break. | high | Single exported constant `MARKER = 'REQUIRES-OPERATOR-INPUT'` in `core/markers.ts`; new lint rule fails on any other token. Tests assert presence via the same constant. | open |
| LOOP-G-X7 | **Signing-key rotation mid-LOOP-G.** A planned key rotation (per RUNBOOK quarterly) during loop development could leave half the artifacts signed by old key, half by new. | low | Sign step is per-emit; running `--sign` at end-of-loop re-signs all artifacts with current key. Manifest carries key fingerprint. | open |
| LOOP-G-X8 | **Submission-bundle role-name collisions.** Adding 11+ new role rows across 6 slices risks name collision with future slices. | low | `submission-bundle.ts` validates role uniqueness; CI guardrail fails on duplicate. Reserve `afr-*` prefix for AFR family. | open |
| LOOP-G-X9 | **Cross-loop test fixture drift.** LOOP-E (ConMon) and LOOP-G (AFR-CCM) both consume `out/poam.json`; if fixtures diverge tests pass independently but fail in integration. | med | Shared fixture under `tests/fixtures/poam-sample/` consumed by both loops; CI integration test runs `--afr-ccm` + `--monthly-conmon` together. | open |
| LOOP-G-X10 | **Tracker route HMAC secret rotation requires operator action.** G.G1 webhook secret is operator-managed; missed rotation reduces security. | low | Tracker shows `secret_age_days` metric; LOOP-I.I1 dashboard surfaces aged secrets. Quarterly RUNBOOK reminder. | open |
| LOOP-G-X11 | **OSCAL v1.1.2 → v1.1.3 minor version bump.** During the LOOP-G implementation window NIST may release v1.1.3; our artifacts cite v1.1.2 in `$schema`. | med | `$schema` URL pinned per artifact; bump in a dedicated slice when v1.1.3 lands; `core/oscal-validate.ts` accepts both via overload. | open |
| LOOP-G-X12 | **Public feedback endpoint (G.G6) discoverability.** If hosted on the tracker's internal URL, customers can't reach it. | high | Operator runbook covers reverse-proxy to the public Trust Center URL; route hardened (rate-limit, CSRF-exempt, no auth). Default tracker config docs the proxy pattern. | open |
| LOOP-G-X13 | **Customer trust-center URL stability for G.G3 + G.G5 + G.G6.** Customers archive bookmarks to `/scg.pdf`, `/oar-2026-Q3.md`, etc. URL changes break customers. | high | URL scheme is operator-fixed; runbook covers permanent redirects. Filenames are deterministic (`oar-<period_id>.json`) so customers can construct future URLs. | open |
| LOOP-G-X14 | **3PAO push-back on dependency-free .docx fidelity.** A 3PAO may prefer a Word-authored template with specific formatting we don't emit. | med | All 3 LOOP-G docx outputs (afr-icp, afr-mas, afr-scg) ship the canonical machine-readable JSON alongside; 3PAO can render their own Word from the JSON if needed; offer `--docx-stylesheet <path>` override hook. | open |
| LOOP-G-X15 | **Subprocessor sheet read failures (G.G4).** If `subprocessors-sheet.ts` Google Sheets reader fails (rate limit, network), G.G4 third-party JSON is incomplete. | med | Cache the last successful sheet read on disk (24h TTL); on cache miss raise diagnostic but don't fail; emit `requires_operator_input` for the third-party section. | open |

---

## Per-slice risks

### G.G1 — AFR-FSI (FedRAMP Security Inbox)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| LOOP-G-G1.R1 | FedRAMP has not published a standardized inbound-webhook schema for FSI senders; each email provider differs. | med | HMAC tracker webhook accepts canonical `{from, to, subject, received_at, headers}`; provider-specific mapping in operator runbook. | open |
| LOOP-G-G1.R2 | DKIM verdict unavailable from some providers (legacy Postfix, custom SMTP). | high | `dkim_pass=null` triggers `held_for_review=1`; never auto-routes; operator triage. | open |
| LOOP-G-G1.R3 | Senior security official email is a single point of failure for FSI-CSO-EMR. | med | RUNBOOK recommends distribution list; v2 will allow multi-recipient array. | open |
| LOOP-G-G1.R4 | Webhook secret quarterly rotation operator-driven; missed rotation could leak. | med | Tracker exposes `secret_age_days`; LOOP-I.I1 surfaces it. Dual-secret window for 24h post-rotation. | open |
| LOOP-G-G1.R5 | SCN-classifier auto-NOC false positives could spam `fsi_message_log`. | low | Rule library scoped to SSP-domain DNS records; unit-tested with negative cases. | open |
| LOOP-G-G1.R6 | Webhook DoS via bad-HMAC floods. | low | Existing tracker rate-limiter (D.1) at 60 req/min/IP. | open |

### G.G2 — AFR-ICP (Incident Communications Procedures)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| LOOP-G-G2.R1 | CISA `myservices.cisa.gov/irf` is a web form, not an API; G.G2 generates a packet the operator manually submits. | high | RUNBOOK covers manual submission workflow; when CISA publishes an API, add a submitter module without shape change. | open |
| LOOP-G-G2.R2 | 1-hour SLA enforcement creates false-positive late_report findings when discovered_at is back-filled (e.g. incident detected by external party Friday, logged Monday). | med | `discovered_at` requires `discovered_by_user_id` + tracker audit log captures real-time entry; back-fill flagged with `late_entry` event but separate from SLA breach. | open |
| LOOP-G-G2.R3 | Agency PoC list staleness; if an agency rotates incident PoC mid-period, our published procedures document is wrong. | high | Tracker `icp_agency_contacts` table has `last_verified_at` column; orchestrator raises diagnostic when any PoC has `last_verified_at > 90d`. | open |
| LOOP-G-G2.R4 | Daily-update cron failure leaves open incidents un-reminded. | high | Cron health-check endpoint; LOOP-I.I1 dashboard tile; on cron failure → all open incidents flagged. | open |
| LOOP-G-G2.R5 | Final report narrative may inadvertently include PII or sensitive details. | high | Tracker UI shows a "PII redaction reminder" before submit; final report is reviewed by operator before flagged published. | open |
| LOOP-G-G2.R6 | CISA attack-vector taxonomy may evolve; classification could become stale. | low | `attack_vector` is a free-text field validated against an operator-supplied enum list; enum updated via tracker config. | open |

### G.G3 — AFR-ADS (Authorization Data Sharing)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| LOOP-G-G3.R1 | 3-year retention enforcement is LOOP-H.H2's responsibility; G.G3 only stamps `retention_expiry` and doesn't delete. | med | Document handoff in slice + RUNBOOK; LOOP-H gates retention audit. | open |
| LOOP-G-G3.R2 | Trust Center vs USDA Connect choice — different artifact-publication semantics. | low | `--trust-center-url` flag supports both; artifact shape is identical. | open |
| LOOP-G-G3.R3 | Service list rows may omit customer-facing services if operator hasn't tagged `customer_facing=true`. | high | Default `customer_facing=false`; orchestrator raises diagnostic when ratio of customer-facing/total is <5%. | open |
| LOOP-G-G3.R4 | Historical-archive append-only invariant could regress (sort order, sha256 computation differ across Node versions). | high | Per-period sha256 verified during emit; archive index validated by `core/oscal-validate.ts`-like ajv pass. | open |
| LOOP-G-G3.R5 | Consistency-check (CBF) false positives if markdown headings reorder. | med | Match by service name (case-insensitive) not by heading order; tested. | open |
| LOOP-G-G3.R6 | `verifyPublishedMatchesLocal` requires network in CI; gated behind `--afr-ads-probe-public`. | low | Default off in CI; runbook covers production-mode probe. | open |
| LOOP-G-G3.R7 | `oar_next_target_date` cross-slice dependency on G.G6 — if G.G6 runs after G.G3, the field is REQUIRES-OPERATOR-INPUT. | high | Orchestrator runs G.G6 before G.G3 OR G.G3 reads `out/afr-ccm/oar-*.json` for the target date. | open |

### G.G4 — AFR-MAS (Minimum Assessment Scope)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| LOOP-G-G4.R1 | Inventory volume explosion in the .docx (>500 assets). | med | `--mas-aggregate` flag; default aggregate when assets>100. | open |
| LOOP-G-G4.R2 | PlantUML grammar drift between versions. | low | Stable subset only; sanity-tested via regex; no full parser dep. | open |
| LOOP-G-G4.R3 | Auto-derived info-flow false positives. | med | Tag `derived: true`; .docx renders in separate "Auto-derived (verify)" subsection. | open |
| LOOP-G-G4.R4 | Subprocessor sheet ⇄ tracker contract-id drift. | high | Emit `subprocessor_sync.json` sidecar listing divergences; surface as finding. | open |
| LOOP-G-G4.R5 | `handles_federal_data` mass-misclassification (operator forgets to tag). | high | Console summary prints ratio; high-severity diagnostic when <5%; tracker UI warns at save time. | open |
| LOOP-G-G4.R6 | Cross-resource UUID alignment with SSP (arn vs self-link vs Azure Resource ID). | high | Define `InventoryRef` union + require SSP components carry `props['inventory-ref']`. | open |
| LOOP-G-G4.R7 | SVG layout becomes unreadable past 30 nodes. | low | `.puml` always-valid alternative; v2 force-directed layout. | open |

### G.G5 — AFR-SCG (Secure Configuration Guide)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| LOOP-G-G5.R1 | FIPS module ID churn (CMVP retires modules to Historical). | high | `status: 'active'|'historical'` field; high-severity diagnostic on Historical inclusion. | open |
| LOOP-G-G5.R2 | Reference-arch outputs diverge across providers naming. | med | Provider-prefixed keys; cross-cloud abstract settings only from control-benchmark overlay. | open |
| LOOP-G-G5.R3 | OOXML rendering at scale (300+ settings → wall of tables). | low | Collapsible subsections per provider; `--scg-truncate-tables N` flag. | open |
| LOOP-G-G5.R4 | Customer-facing narrative version drift. | med | Version-history section + sha256 of every published version. | open |
| LOOP-G-G5.R5 | OSCAL Component Definition mapping mismatch (per LOOP-G-SPEC §6.3). | low | Ship flat baseline now; defer OSCAL CD emit to `--scg-oscal` follow-up. | open |
| LOOP-G-G5.R6 | PDF rendering without external dep. | med | Defer to LOOP-E.E1 pure-JS PDF emitter; LibreOffice fallback documented. | open |
| LOOP-G-G5.R7 | SCG-CSO-AUP placement — instructions must be in the authorization package. | low | `afr-scg-use-instructions` bundle entry `required: true`; INDEX.json tags it explicitly. | open |

### G.G6 — AFR-CCM (Continuous Monitoring per 20x)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| LOOP-G-G6.R1 | OAR aggregation rules under-specified by FedRAMP. | med | Tunable thresholds in `org-profile.yaml:ccm.thresholds`; aggregation function exposed. | open |
| LOOP-G-G6.R2 | OAR PDF rendering without external dep. | med | Ship .md + .json; operator renders via pandoc / LibreOffice; LOOP-E.E1 PDF emitter follow-up. | open |
| LOOP-G-G6.R3 | Feedback channel abuse / spam. | high | Rate limiter 5/IP/h; body length cap; operator-curated spam blocklist. | open |
| LOOP-G-G6.R4 | Anonymization cron failure leaves PII at rest. | high | REO pre-flight fails orchestrator run when rows >24h have non-null internal-timestamp column; cron health monitored. | open |
| LOOP-G-G6.R5 | `.ics` parsing differences (Google Calendar, Outlook, Apple Calendar). | med | Test against RFC-5545 parser; document tested clients in runbook. | open |
| LOOP-G-G6.R6 | Period boundary ambiguity (UTC vs operator timezone). | med | Inclusive-start / exclusive-end UTC; documented in OAR footer. | open |
| LOOP-G-G6.R7 | OAR + LOOP-E.E1 monthly delivery divergence (same data, two cadences). | high | Both call same exporters; integration test asserts Q3 OAR = sum of Jul+Aug+Sep monthly. | open |
| LOOP-G-G6.R8 | Month arithmetic edge cases (Feb 29, Jan 31 + 3 → Apr 30). | high | Explicit unit tests; `Date.UTC` consistently. | open |

---

## External dependencies that may change

- **FedRAMP FRMR `documentation.json` updates** — v0.9.43-beta → v1.0 release expected H2-2026. Any FRMR id change or MUST text revision invalidates verbatim `provenance.requirementTexts` blocks. Watch the `FedRAMP/docs` repo.
- **FedRAMP RFC-0006 (FSI)** — could publish a standard sender format / inbound-webhook schema. Today our `classifyFsiMessage` derives from subject prefix; a standardized JSON envelope would let us validate body structure.
- **FedRAMP RFC-0014 (KSI)** — Phase Two finalization could change OAR aggregation rules or required `summary_sections` content. Loop our re-validation against the published rule when it lands.
- **FedRAMP RFC-0024 (Machine-Readable Submissions)** — could mandate specific OSCAL extensions for AFR artifacts.
- **CISA Federal Incident Notification Guidelines** — attack-vector taxonomy can be updated; our `attack_vector` enum reads against the operator-supplied list with the published taxonomy as default.
- **CISA Incident Reporting System (myservices.cisa.gov/irf)** — currently web form; an API rollout would let us auto-submit incident reports (G.G2 wraps the data accordingly).
- **NIST CMVP module list** — CMVP routinely retires modules to Historical status. G.G5 must detect and surface.
- **NIST SP 800-53 Rev 5 / 5.x** — minor revisions to CA-7, IR-6, CM-2, CM-6 could shift control mappings.
- **NIST SP 800-53A Rev 5.2.0 → 5.3.0** — assessment procedures update affects G.G3 service-list field requirements.
- **OSCAL v1.1.2 → v1.1.3** — schema URL pinned per artifact; bump in dedicated slice.
- **RFC 5545 (iCalendar)** — stable; very unlikely to change.
- **ECMA-376 (Office Open XML)** — stable; very unlikely to change.
- **`ajv` major version** (currently 8.x) — major bump may change validator API; tested in `oscal-validate.ts` pin.
- **`subprocessors-sheet.ts` Google Sheets API** — quota changes could affect runs; cached 24h.
- **Trust Center vendor APIs (USDA Connect.gov)** — if the API changes, G.G3 `verifyPublishedMatchesLocal` regex needs update.

---

## Resolved risks (historical)

(Empty — populated as risks are resolved. Each entry includes: ID, resolution date, commit hash, resolution note, follow-up reference.)

---

## Risk lifecycle conventions

- **open** — risk is known and a mitigation is documented but not exercised in production.
- **mitigated** — mitigation is in place and tested; risk still exists but is bounded.
- **resolved** — root cause eliminated; risk no longer applies.
- **accepted** — risk acknowledged and not mitigated; operator decision recorded.

When changing status, include in this file:
- New status keyword
- Date
- Commit hash (if code change)
- Resolution note (one sentence)
- Cross-reference to slice doc Implementation log if applicable
