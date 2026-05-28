# ADS, MAS & KSI-CSX — Collector Design Analysis

**Scope:** all 28 requirements in **ADS** (Authorization Data Sharing, 20), **MAS** (Minimum Assessment Scope, 5), and **KSI-CSX** (the CSX summary requirements: SUM, MAS, ORD — 3). FRMR `v0.9.0-beta` / 2026 Consolidated Rules preview.

## Overview

These three families are dominated by **governance and scoping** obligations, not cloud-config that a read-only collector can scan. ADS is about *where and how* authorization data is published (Trust Center / USDA Connect Community Portal / FedRAMP Marketplace) and *who* can reach it; MAS is about *defining* the assessment boundary (which information resources are in the cloud service offering); KSI-CSX is about *maintaining summaries* and *ordering* the KSI work. The actor on most ADS requirements is **TRC** (the Trust Center service) or **UTC/CSL** — and our org's CSP/SaaS-on-AWS+GCP+K8s footprint is the *consumer/publisher* side, not the Trust Center operator. A FedRAMP-compatible Trust Center is frequently a **third-party SaaS** (Paramify, SafeBase, Vanta Trust Center, etc.), so most ADS requirements are inherited/attestation against a vendor, with the artifact being the published endpoint plus the vendor's own attestation.

**What is genuinely automatable here is thin but real:**
- **ADS-CSO-PUB / ADS-CSO-SVC / ADS-UTC-PGD / ADS-CSL-UCP / ADS-CSX-UTC / ADS-TRC-PAC / ADS-TRC-HMR** — the *existence and reachability* of a published Trust Center / public CSO page / machine-readable (OSCAL/JSON) endpoint / documented API can be probed read-only over HTTPS (HEAD/GET + content-type + OSCAL schema sniff). This is a **new lightweight HTTP/endpoint probe**, not a cloud-SDK collector.
- **MAS-CSO-IIR / MAS-CSO-FLO / MAS-CSO-TPR** — the *documented* boundary cannot be tested, but it can be **cross-checked against discovered inventory**: AWS Config Aggregator + GCP Cloud Asset Inventory (already collected by `providers/{aws,gcp}/inventory.ts` for KSI-PIY-GIV) enumerate live resources. A reconciliation diff (`discovered − documented`) surfaces *undocumented* resources (boundary gaps) and *documented-but-undiscovered* (drift / decommissioned), and the third-party SaaS subprocessor list (`core/subprocessors-sheet.ts`, `core/detect/third-party-tools.ts`) feeds MAS-CSO-TPR.
- **KSI-CSX-SUM** — already partly implemented by `core/csx-sum-aggregator.ts`; it is the one CSX requirement that is meaningfully *machine-generated* from the collector's own per-KSI evidence files.
- **KSI-CSX-MAS / KSI-CSX-ORD** — meta/governance: SUM "applies all KSIs within MAS" is a **coverage cross-check** (does the collector run a KSI for every in-MAS resource class?); ORD is a non-testable MAY ordering recommendation.

**Level model.** All 28 carry `low.applies = true` and `moderate.applies = true` from the dump (`source: 20x-machine-readable`). **High is DERIVED**: every record has `high.applies = null` with `source: derived-rev5-pending` and `controls: []` — there is no Rev5 High baseline mapping in the dump for any ADS/MAS/KSI requirement (these are 20x/both-track process requirements that predate a NIST 800-53 Rev5 High crosswalk). So for **all 28**, High = "derived — pending; no `controls[]` to derive from (n/a)". This must be stated explicitly per requirement rather than asserted as a real High obligation.

**Read-only constraint.** Nothing here writes. The only new I/O is **outbound HTTPS GET/HEAD to public CSP/Trust-Center URLs** the operator supplies in config — read-only by construction, no cloud mutation, no credentials.

---

## Coverage table

| ID | Name | L/M/H | Testability | Primary signal |
|----|------|-------|-------------|----------------|
| ADS-CSL-LRE | Legacy Repository Exception | ✓/✓/derived | process-artifact | Applicability flag (High + legacy repo) → opt-out attestation |
| ADS-CSL-TCM | Trust Center Migration | ✓/✓/derived | process-artifact | Migration-notice artifact + USDA Connect folder content |
| ADS-CSL-UCP | USDA Connect | ✓/✓/derived | hybrid | Trust Center present → exempt; else USDA Connect upload attestation |
| ADS-CSL-UTC | Use Trust Centers (SHOULD) | ✓/✓/derived | hybrid | Reachable FedRAMP-compatible Trust Center endpoint |
| ADS-CSO-CBF | Consistency Between Formats | ✓/✓/derived | hybrid | Automation pipeline artifact; HR vs MR field diff probe |
| ADS-CSO-HAD | Historical Authorization Data | ✓/✓/derived | process-artifact | 3-yr version history present in Trust Center (probe versions endpoint) |
| ADS-CSO-PUB | Public Information | ✓/✓/derived | hybrid | Public CSO page reachable w/ required fields + machine-readable variant |
| ADS-CSO-RIS | Responsible Information Sharing | ✓/✓/derived | process-artifact | Sensitivity-review attestation (no automatable signal) |
| ADS-CSO-SVC | Service List | ✓/✓/derived | hybrid | Public service list reachable; cross-check vs discovered service inventory |
| ADS-CSX-UTC | Use Trust Centers (MUST, 20x) | ✓/✓/derived | hybrid | Reachable FedRAMP-compatible Trust Center endpoint |
| ADS-TRC-AAI | Agency Access Inventory | ✓/✓/derived | process-artifact | Trust Center (vendor) feature attestation |
| ADS-TRC-ACL | Access Logging | ✓/✓/derived | process-artifact | Trust Center (vendor) access-log retention attestation |
| ADS-TRC-HMR | Human + Machine-Readable (SHOULD) | ✓/✓/derived | hybrid | Both HR + MR formats downloadable from Trust Center |
| ADS-TRC-PAC | Programmatic Access | ✓/✓/derived | hybrid | Documented API endpoint reachable + content-type |
| ADS-TRC-RSP | Responsive Performance (SHOULD) | ✓/✓/derived | hybrid | Endpoint latency/availability probe (uptime) |
| ADS-TRC-SSM | Self-Service Access Mgmt (SHOULD) | ✓/✓/derived | process-artifact | Trust Center (vendor) self-service feature attestation |
| ADS-TRC-USH | Uninterrupted Sharing | ✓/✓/derived | hybrid | Trust Center uptime probe + vendor SLA attestation |
| ADS-UTC-AAD | Agency Access Denial | ✓/✓/derived | process-artifact | Denial-notification log (5-business-day email to FedRAMP) |
| ADS-UTC-AGA | Agency Access (SHOULD) | ✓/✓/derived | process-artifact | Access-request fulfillment attestation |
| ADS-UTC-PGD | Public Guidance | ✓/✓/derived | hybrid | Public plain-language access-guidance page reachable |
| KSI-CSX-MAS | Application within MAS (SHOULD) | ✓/✓/derived | hybrid | Coverage cross-check: KSI run per in-MAS resource class |
| KSI-CSX-ORD | AFR Order of Criticality (MAY) | ✓/✓/derived | process-artifact | Non-testable ordering recommendation |
| KSI-CSX-SUM | Implementation Summaries | ✓/✓/derived | hybrid | Auto-generated per-KSI summary (csx-sum-aggregator.ts) |
| MAS-CSO-FLO | Information Flows & Sec Objectives | ✓/✓/derived | hybrid | Documented data-flow doc; cross-check vs network/inventory discovery |
| MAS-CSO-IIR | Identify Information Resources | ✓/✓/derived | hybrid | Documented IR set; reconcile vs Config/Asset inventory |
| MAS-CSO-MDI | Metadata Inclusion | ✓/✓/derived | process-artifact | Conditional flag (only if IIR applies) — scoping attestation |
| MAS-CSO-SUP | Supplemental Information (MAY) | ✓/✓/derived | process-artifact | Optional supplement — marking/separation attestation |
| MAS-CSO-TPR | Third-Party Information Resources | ✓/✓/derived | hybrid | Documented 3pp list; cross-check vs subprocessor sheet + tool detector |

**Testability totals (28):** process-artifact = **13**, hybrid = **15**, api-testable = **0**. (No requirement is purely cloud-SDK-testable; the "hybrid" ones gain a real automated signal from an HTTP endpoint probe or an inventory cross-check, but always need a human-attached artifact to fully satisfy.)

---

### ADS-CSL-LRE — Legacy Repository Exception  [MAY]
- **Track / actor / levels:** rev5 / CSL / L:✓ M:✓ H:derived(rev5: n/a — controls[]=∅)
- **Requirement (plain English):** A provider of a *Rev5-Authorized* cloud service offering at **FedRAMP High** that still uses a legacy self-managed repository for *authorization data* (the collective info FedRAMP needs for assessment) MAY ignore the entire ADS process until further notice.
- **Testability:** process-artifact
- **Automated validation:** None — pure applicability carve-out. Tracker records two booleans (impact-level == High, using-legacy-repo) and, if both true, marks the whole ADS family `not-applicable` with the exception cited. Our org is a 20x participant (not Rev5-High-legacy), so this exception almost certainly does **not** apply; tracker should default it `false` and surface ADS as in-scope.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** n/a (it *is* the satisfier — an opt-out).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker (applicability gate feeding the orchestrator's coverage-check so it doesn't flag the rest of ADS as failing when the exception is claimed).
- **Recommended implementation:** process-artifact-tracker; a MAY exception with no signal; effort S.

### ADS-CSL-TCM — Trust Center Migration  [MUST]
- **Track / actor / levels:** rev5 / CSL / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** When migrating to a *Trust Center* (secure repo/service that is the definitive source for authorization data), a provider MUST notify *all necessary parties* (always FedRAMP + any agency customer operating the CSO) AND place instructions in their existing USDA Connect Community Portal secure folders explaining how to use the Trust Center.
- **Testability:** process-artifact
- **Automated validation:** Event-scoped (only at migration). Tracker stores the migration-notification record (recipients, date) and a copy/screenshot of the USDA Connect folder content. A weak automated signal: probe the Trust Center URL to confirm it is *now live* (corroborates a migration occurred), but the notice itself is not observable.
- **Required permissions & error handling:** n/a — process artifact (USDA Connect is access-gated, not scrapeable).
- **Alternative satisfiers:** Trust Center vendor's "notify subscribers" feature export as proof of party notification.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker; optional endpoint-probe corroboration via the ADS HTTP probe.
- **Recommended implementation:** process-artifact-tracker; event-based with no standing signal; effort S.

### ADS-CSL-UCP — USDA Connect  [MUST]
- **Track / actor / levels:** rev5 / CSL / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST share authorization data via the USDA Connect Community Portal **UNLESS** they use a FedRAMP-compatible Trust Center.
- **Testability:** hybrid
- **Automated validation:** Two-branch. If the ADS HTTP probe confirms a reachable FedRAMP-compatible Trust Center (see ADS-CSX-UTC), this requirement is *satisfied-by-exception* and the tracker auto-flips it to met. Otherwise it falls back to a process artifact: attestation + screenshot that authorization data is uploaded to the USDA Connect secure folder. The Trust-Center branch is automatable; the USDA-Connect branch is not (access-gated portal).
- **Required permissions & error handling:** n/a for cloud; the HTTP probe needs only outbound 443. Probe failures classified like API errors (timeout/DNS/404 → "endpoint unreachable", not a compliance fail by itself).
- **Alternative satisfiers:** FedRAMP-compatible Trust Center (Paramify, SafeBase, Vanta Trust Center) — detectable via the configured endpoint probe.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new ADS endpoint-probe module + process-artifact tracker for the USDA-Connect branch.
- **Recommended implementation:** hybrid (endpoint-probe for the exception branch, artifact for the default); effort M.

### ADS-CSL-UTC — Use Trust Centers  [SHOULD]
- **Track / actor / levels:** rev5 / CSL / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers SHOULD use a FedRAMP-compatible Trust Center to store and share authorization data with all necessary parties. (Rev5 SHOULD twin of the 20x MUST in ADS-CSX-UTC; `fka` ADS-CSX-UTC.)
- **Testability:** hybrid
- **Automated validation:** Same signal as ADS-CSX-UTC — probe the operator-configured Trust Center URL: reachable (2xx), TLS valid, and (bonus) advertises FedRAMP compatibility (look for a `/.well-known/`, OSCAL link, or known-vendor host). SHOULD severity = `medium` rather than `high`.
- **Required permissions & error handling:** n/a — outbound HTTPS probe only.
- **Alternative satisfiers:** USDA Connect Community Portal usage (the fallback path) satisfies the underlying sharing intent; recorded as artifact.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new ADS endpoint-probe module (shared with ADS-CSX-UTC; emit one finding tagged to both IDs).
- **Recommended implementation:** hybrid (endpoint-probe + artifact); effort S given it shares code with ADS-CSX-UTC.

### ADS-CSO-CBF — Consistency Between Formats  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** When authorization data is provided in both *human-readable* and *machine-readable* (44 USC §3502(18) — computer-processable without losing semantic meaning) formats, providers MUST use **automation** to keep the two consistent.
- **Testability:** hybrid
- **Automated validation:** If the ADS probe can fetch both the HR page and the MR (OSCAL/JSON) variant, the collector can do a **field-level reconciliation** of overlapping fields (service list, OAR date, contact info, marketplace link) and flag divergence — that *is* a consistency signal. Proof of the *automation pipeline* itself (CI job that regenerates MR from a single source) remains an attached artifact (pipeline config / commit history).
- **Required permissions & error handling:** n/a for cloud; HTTP probe only. Distinguish "MR endpoint absent" (precondition not met → finding n/a) from "fields diverge" (real fail).
- **Alternative satisfiers:** GRC/Trust-Center tooling (Paramify, SafeBase) that single-sources both formats — attest the tool's generation pipeline.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new ADS endpoint-probe module (HR-vs-MR differ); process-artifact tracker for the pipeline proof.
- **Recommended implementation:** hybrid (probe-based diff + pipeline artifact); effort M.

### ADS-CSO-HAD — Historical Authorization Data  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST keep historical versions of authorization data available to all necessary parties for **three years** (unless FedRAMP says otherwise); deltas MAY be consolidated quarterly.
- **Testability:** process-artifact (with a weak probe assist)
- **Automated validation:** If the Trust Center exposes a versions/history endpoint, the probe can confirm versioned entries exist and count back ~3 years (timestamps on listed versions). Retention *guarantee* itself is a vendor attestation. Mostly artifact.
- **Required permissions & error handling:** n/a — outbound HTTPS probe of a versions endpoint if one is documented.
- **Alternative satisfiers:** Trust Center vendor version-history feature; or an internal immutable store (S3 with Object Lock / versioning — but note that store is internal, not the public sharing surface, so it's supporting evidence only).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker; optional probe of versions endpoint in the ADS module.
- **Recommended implementation:** process-artifact-tracker (probe is best-effort corroboration); effort S.

### ADS-CSO-PUB — Public Information  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST publicly share up-to-date CSO info in **both HR and MR formats**, including at least: FedRAMP Marketplace link, Service Model, Deployment Model, Business Category, UEI number, contact info, overall service description, the detailed service list (ADS-CSO-SVC), customer-responsibility/secure-config summary, Trust Center access process, Trust Center availability status + support info, and next OAR date (CCM-OAR-NRD). Generally a public webpage.
- **Testability:** hybrid
- **Automated validation:** Strongest automatable ADS requirement. The ADS probe GETs the operator-configured public CSO URL and checks: HTTP 2xx, presence of a machine-readable variant (content-negotiation or a linked `.json`/OSCAL doc), and a **field-presence checklist** against the 13 required fields above (regex/JSON-key presence; e.g. a `marketplace.fedramp.gov` link, a UEI pattern, an OAR date). Emits per-field pass/fail. "Up-to-date" is partly checkable (OAR date in the future / recent last-modified).
- **Required permissions & error handling:** n/a — outbound HTTPS only. Treat probe-network errors as `warning` (unreachable ≠ noncompliant), missing required fields as `fail`.
- **Alternative satisfiers:** Trust Center / public trust page that renders these fields (SafeBase, Paramify public page) — same probe applies to that URL.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new ADS endpoint-probe module (this is the anchor collector for the family); checklist config lists the 13 fields.
- **Recommended implementation:** hybrid → leaning collector (the field-presence probe is genuinely useful) + artifact for content accuracy; effort M.

### ADS-CSO-RIS — Responsible Information Sharing  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Authorization data MUST contain enough info to support authorization decisions but SHOULD NOT include sensitive info that would *likely* (a reasonable degree of probability) let a threat actor gain access, cause harm, disrupt, or otherwise adversely impact the CSO.
- **Testability:** process-artifact
- **Automated validation:** None reliable. A red-team-style secret/PII scan of the *published* MR doc (detect-secrets/gitleaks patterns over the fetched OSCAL JSON) could flag obvious leakage of credentials/IPs/keys — a useful *guardrail*, not a compliance proof. The substantive judgment (sufficient-but-not-sensitive) is human. Treat any scan hit as a high-severity *advisory*, not the pass/fail.
- **Required permissions & error handling:** n/a — operates on already-fetched public MR document.
- **Alternative satisfiers:** Documented sensitivity-review process (a checklist sign-off before publish); GRC tool with a redaction/review gate.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** process-artifact tracker; optional secret-scan over the ADS-probe-fetched MR doc.
- **Recommended implementation:** process-artifact-tracker (with advisory secret scan); effort S.

### ADS-CSO-SVC — Service List  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST publicly share a detailed list of the specific services (with clear feature/service names matching public marketing) and their security objectives in the CSO — complete enough for a customer to tell what is and isn't in the *Minimum Assessment Scope* without requesting underlying authorization data.
- **Testability:** hybrid
- **Automated validation:** Probe fetches the public service list, then **cross-checks against discovered service inventory** from `providers/{aws,gcp}/inventory.ts` (AWS Config Aggregator resource types; GCP Cloud Asset Inventory asset types) and the MAS-CSO-IIR documented IR set. Flag: live AWS/GCP service classes that customers can reach but are *absent* from the public list (under-disclosure), and listed services with no discovered backing (stale list). This is the same reconciliation engine as MAS-CSO-IIR, reused.
- **Required permissions & error handling:** Inventory side reuses existing collectors (AWS `config:Describe*`/`config:Get*`, GCP `cloudasset.assets.list` / `roles/cloudasset.viewer`) — diagnostics already centralized in `error-diagnostics.ts`. The list side is HTTPS-only.
- **Alternative satisfiers:** Trust Center/marketplace-rendered service catalog generated from a single source of truth (attest generation).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new ADS endpoint-probe module + reuse `inventory.ts` discovery + MAS reconciliation engine.
- **Recommended implementation:** hybrid (probe + inventory cross-check); effort M.

### ADS-CSX-UTC — Use Trust Centers  [MUST]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST use a FedRAMP-compatible Trust Center to store and share authorization data with all necessary parties. (20x MUST; `fka` FRR-ADS-07.)
- **Testability:** hybrid
- **Automated validation:** Probe the operator-configured Trust Center URL: reachable, TLS valid, and FedRAMP-compatibility heuristics (known-vendor host, advertised OSCAL/programmatic endpoint per ADS-TRC-PAC, a public access-guidance page per ADS-UTC-PGD). The *compatibility certification* of the Trust Center is a vendor attestation, but liveness + capability presence is observable. This is the canonical ADS endpoint collector; ADS-CSL-UTC/UCP key off the same finding.
- **Required permissions & error handling:** n/a — outbound HTTPS. Unreachable → warning; reachable-but-no-MR/API-capability → fail.
- **Alternative satisfiers:** None for a 20x MUST (USDA Connect is the Rev5 path, not 20x). Different *vendors* are the variability, all detectable via configured URL.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new ADS endpoint-probe module (anchor); shares finding with ADS-CSL-UTC/UCP and capability checks from TRC-PAC/HMR.
- **Recommended implementation:** hybrid (endpoint-probe + vendor compatibility attestation); effort M.

### ADS-TRC-AAI — Agency Access Inventory  [MUST]
- **Track / actor / levels:** both / **TRC** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Trust Centers MUST maintain an inventory + history of federal *agency* (44 USC §3502(1)) users/systems with access to authorization data and make it available to FedRAMP without interruption.
- **Testability:** process-artifact
- **Automated validation:** None for us — actor is TRC (the Trust Center service). As CSP consumers of a third-party Trust Center this is **inherited**; the artifact is the vendor's attestation/feature evidence (access-inventory export). If we self-host a Trust Center it becomes a build obligation, but that's out of our SaaS scope.
- **Required permissions & error handling:** n/a — process/inherited.
- **Alternative satisfiers:** Trust Center vendor's audit/access-inventory feature (SafeBase/Paramify access logs) — attach export as evidence; or vendor SOC2/FedRAMP letter covering the capability.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker (vendor-inherited evidence slot).
- **Recommended implementation:** process-artifact-tracker (inherited from Trust Center vendor); effort S.

### ADS-TRC-ACL — Access Logging  [MUST]
- **Track / actor / levels:** both / **TRC** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Trust Centers MUST log access to authorization data and store access summaries for ≥6 months; per-party info SHOULD be available on that party's request.
- **Testability:** process-artifact
- **Automated validation:** None for us — TRC actor, inherited from the Trust Center vendor. Artifact = vendor access-log retention attestation (and, if self-hosted, the log store config). No CSP-side cloud signal.
- **Required permissions & error handling:** n/a — inherited.
- **Alternative satisfiers:** Vendor access-log export + retention policy; or, if Trust Center fronted by our own infra, CloudTrail/Cloud Audit Logs on the bucket — but that's the *hosting* layer, supporting evidence only.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker (vendor-inherited).
- **Recommended implementation:** process-artifact-tracker; effort S.

### ADS-TRC-HMR — Human and Machine-Readable  [SHOULD]
- **Track / actor / levels:** both / **TRC** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Trust Centers SHOULD make authorization data viewable and downloadable in both HR and MR formats.
- **Testability:** hybrid
- **Automated validation:** Probe the Trust Center: fetch the HR view (2xx, text/html) AND confirm an MR download (OSCAL/JSON, `application/json`/`+oscal`). Two-format availability is directly observable. SHOULD → `medium` severity.
- **Required permissions & error handling:** n/a — outbound HTTPS; content-type sniff. MR absent → fail (medium); both present → pass.
- **Alternative satisfiers:** Vendor capability attestation if downloads are auth-gated and not anonymously probeable.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** ADS endpoint-probe module (capability check feeding ADS-CSX-UTC compatibility heuristic).
- **Recommended implementation:** hybrid (probe + fallback attestation); effort S (shares probe code).

### ADS-TRC-PAC — Programmatic Access  [MUST]
- **Track / actor / levels:** both / **TRC** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Trust Centers MUST provide documented programmatic (API) access to **all** authorization data, including programmatic access to human-readable materials.
- **Testability:** hybrid
- **Automated validation:** Probe the documented API endpoint (operator-supplied API URL / OpenAPI/`.well-known` doc): reachable, returns machine-readable payload, and API docs exist (fetch the documentation URL). "All data via API including HR materials" is partly checkable (does the API expose a HR-doc retrieval route?). Certification is vendor attestation.
- **Required permissions & error handling:** n/a — outbound HTTPS to the public/documented API. 401/403 from the API is expected (auth-gated) and should be treated as "endpoint present, access-gated" (pass on existence) rather than fail.
- **Alternative satisfiers:** Vendor API + published OpenAPI spec; FedRAMP Marketplace machine-readable package endpoint.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** ADS endpoint-probe module (API-presence check).
- **Recommended implementation:** hybrid (probe + vendor attestation); effort S.

### ADS-TRC-RSP — Responsive Performance  [SHOULD]
- **Track / actor / levels:** both / **TRC** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Trust Centers SHOULD deliver responsive performance under normal conditions and minimize disruptions.
- **Testability:** hybrid
- **Automated validation:** The probe already records request latency + status for the Trust Center URL; aggregate over scheduled runs into an availability/latency rollup (e.g. p95 response time, uptime % over the run history in the tracker DB). This is a *trend*, not a single pass/fail — set a soft threshold. SHOULD → advisory.
- **Required permissions & error handling:** n/a — outbound HTTPS; latency captured by the probe.
- **Alternative satisfiers:** Vendor status page / SLA / uptime report (status.* endpoint scrape).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** ADS endpoint-probe module (latency capture) + tracker DB for trend; reuse `core/anomaly.ts` baseline pattern for drift.
- **Recommended implementation:** hybrid (probe latency trend + vendor SLA); effort S.

### ADS-TRC-SSM — Self-Service Access Management  [SHOULD]
- **Track / actor / levels:** both / **TRC** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Trust Centers SHOULD include features that encourage all necessary parties to provision and manage their own access to authorization data directly.
- **Testability:** process-artifact
- **Automated validation:** None — a UX/feature property of the vendor Trust Center, not externally observable. Vendor feature attestation (self-service request workflow).
- **Required permissions & error handling:** n/a — inherited/process.
- **Alternative satisfiers:** Vendor self-service portal feature docs (SafeBase/Paramify request workflow).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker (vendor-inherited).
- **Recommended implementation:** process-artifact-tracker; effort S.

### ADS-TRC-USH — Uninterrupted Sharing  [MUST]
- **Track / actor / levels:** both / **TRC** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Trust Centers MUST share authorization data with all necessary parties without interruption.
- **Testability:** hybrid
- **Automated validation:** Same uptime/availability probe as ADS-TRC-RSP, but MUST severity. The scheduled probe records reachability each run → uptime % over the tracker history; sustained outages flag. The *guarantee* is a vendor SLA attestation, but observed uptime is a real signal.
- **Required permissions & error handling:** n/a — outbound HTTPS reachability; sustained network failure across runs → fail.
- **Alternative satisfiers:** Vendor SLA + status-page history.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** ADS endpoint-probe module (reachability) + tracker DB uptime rollup.
- **Recommended implementation:** hybrid (uptime probe + vendor SLA); effort S.

### ADS-UTC-AAD — Agency Access Denial  [MUST]
- **Track / actor / levels:** both / UTC / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST notify FedRAMP (email info@fedramp.gov) within **5 business days** of denying an *agency* access request for authorization data.
- **Testability:** process-artifact
- **Automated validation:** None — event-driven human action. Tracker holds a denial register: each denial event with date-denied, date-notified, and proof (sent email). A timeliness check can flag any record where (notified − denied) > 5 business days — that's a *tracker rule*, not a cloud signal.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Ticketing/CRM workflow that auto-emails FedRAMP on denial (could integrate with `core/ticket-push.ts` to *record* the event, but the obligation is procedural).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker (denial register with SLA-timeliness rule).
- **Recommended implementation:** process-artifact-tracker; effort S.

### ADS-UTC-AGA — Agency Access  [SHOULD]
- **Track / actor / levels:** both / UTC / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers SHOULD share the *authorization package* (44 USC §3607(b)(8) essential info an agency uses to authorize) with agencies upon request.
- **Testability:** process-artifact
- **Automated validation:** None observable — fulfillment of inbound requests. Tracker logs access-request fulfillment (request date, package shared date, requester). SHOULD → advisory.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Trust Center self-service access (ADS-TRC-SSM) makes this automatic — if a Trust Center grants package access on request, attest that workflow.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker (request register).
- **Recommended implementation:** process-artifact-tracker; effort S.

### ADS-UTC-PGD — Public Guidance  [MUST]
- **Track / actor / levels:** both / UTC / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST publicly provide plain-language policies/guidance for all necessary parties explaining how to obtain and manage access to authorization data stored in the Trust Center.
- **Testability:** hybrid
- **Automated validation:** Probe the operator-configured public guidance URL: reachable (2xx), text/html, and contains access-process keywords ("request access", "manage access", "authorization data"). Presence + reachability observable; plain-language *quality* is human. Feeds the ADS-CSX-UTC compatibility heuristic (a compatible Trust Center should have this page).
- **Required permissions & error handling:** n/a — outbound HTTPS; unreachable → warning, missing keywords → fail.
- **Alternative satisfiers:** Trust Center vendor's built-in access-guidance page (probe that URL instead).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** ADS endpoint-probe module (guidance-page check).
- **Recommended implementation:** hybrid (probe presence + content accuracy artifact); effort S.

### KSI-CSX-MAS — Application within MAS  [SHOULD]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers SHOULD apply **ALL** Key Security Indicators to **ALL** aspects of the CSO that are within the *FedRAMP Minimum Assessment Scope*.
- **Testability:** hybrid
- **Automated validation:** This is a **coverage meta-check** the collector is well placed to do. Cross-reference (a) the set of KSIs the orchestrator actually runs (from `core/ksi-map.ts` + `core/coverage-check.ts`) against the full FRMR KSI catalog, and (b) the resources each collector evaluated against the MAS-CSO-IIR documented in-scope IR set and the discovered inventory. Flag KSIs with no collector and in-MAS resource classes that no KSI touched. Reuses the existing `coverage-check.ts` and the MAS reconciliation engine.
- **Required permissions & error handling:** n/a directly — consumes already-collected evidence + inventory. Inventory permissions are those of `inventory.ts`.
- **Alternative satisfiers:** GRC platform that maps all KSIs to scoped assets (Paramify) — attest its coverage matrix.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** extend `core/coverage-check.ts` + MAS reconciliation engine + `core/ksi-map.ts`.
- **Recommended implementation:** collector (coverage cross-check, no new I/O); effort M.

### KSI-CSX-ORD — AFR Order of Criticality  [MAY]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MAY approach Authorization by KSIs in this order of criticality for an initial package: MAS → ADS → UCM → VDR → SCN → PVA → RSC → CCM → FSI → ICP.
- **Testability:** process-artifact
- **Automated validation:** None — a sequencing *recommendation* for the authorization journey, not a state of the environment. At most, the tracker can use this ordering to **prioritize/sort the gap backlog** (present MAS/ADS/UCM gaps first), which is a UX nicety, not a compliance signal.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** n/a (a MAY recommendation).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** optional sort key in tracker dashboard / `core/findings.ts` prioritization; no collector.
- **Recommended implementation:** process-artifact-tracker (informational ordering only); effort S.

### KSI-CSX-SUM — Implementation Summaries  [MUST]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST maintain simple high-level summaries for **each** KSI of at least: (1) implementation+validation **goals incl. clear pass/fail criteria and traceability**; (2) the **consolidated information resources** validated (e.g. "all employees with privileged access in the Admin group"); (3) the **machine-based** validation processes + their *persistent* cycle (or why N/A); (4) the **non-machine-based** validation processes + cycle (or why N/A); (5) **current implementation status**; (6) any **clarifications/responses to the assessment summary**. (`Persistent Validation` = systematic, persistent validation that resources operate securely against KSIs.)
- **Testability:** hybrid
- **Automated validation:** The most automatable CSX requirement; partly built already (see "Current state" note below). The collector auto-derives per KSI: pass/fail criteria (finding rule names + severity), consolidated resources (from `gap.affected_resources` + finding observations), machine-based cycle (the collector's schedule, e.g. daily/3-day for Moderate), status (last pass/fail), and validation module. The **non-machine-based process** and **assessment clarifications** are human inputs the tracker must collect and merge.
- **Required permissions & error handling:** n/a — reads existing `KSI-*.json` evidence files.
- **Alternative satisfiers:** Paramify / GRC authoring tool that maintains these summaries (detected by `third-party-tools.ts`, where Paramify already maps to `KSI-CSX-SUM`).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a. (Summaries themselves feed the OSCAL emitter in `core/oscal.ts`.)
- **Module connections:** **extend `core/csx-sum-aggregator.ts`** (close the gaps below) + tracker for human-authored fields.
- **Recommended implementation:** hybrid (auto-generate machine fields + tracker for human fields); effort M.

### MAS-CSO-FLO — Information Flows and Security Objectives  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST clearly identify, document, and explain *information flows* and *security objectives* for ALL *information resources* (or sets thereof) in the CSO. ("Handle" = any action on info; third-party IRs included.)
- **Testability:** hybrid
- **Automated validation:** The *documentation* (data-flow diagram + CIA objectives) is a human artifact, but the collector can **corroborate the flows** from discovered topology: VPC/subnet/peering/firewall data from `providers/{aws,gcp}/network.ts`, plus the inventory from `inventory.ts`. Reconcile documented flows vs discovered network edges → flag undocumented connectivity (e.g. a peering or public egress not in the data-flow doc). It cannot *assign* security objectives.
- **Required permissions & error handling:** reuse `network.ts` collectors (AWS `ec2:Describe*` for VPC/SG/peering; GCP `compute.networks/firewalls.list`) and `inventory.ts`; diagnostics via `error-diagnostics.ts`.
- **Alternative satisfiers:** CSPM (Wiz/Lacework) topology export; or a maintained architecture-as-code (Terraform graph) — attest.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new MAS reconciliation engine consuming `network.ts` + `inventory.ts`; process-artifact tracker for the flow doc + objectives.
- **Recommended implementation:** hybrid (topology corroboration + doc artifact); effort L.

### MAS-CSO-IIR — Identify Information Resources  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST identify the set of information resources to assess — all IRs *likely* to handle *federal customer data* or *likely* to impact its CIA. That set **is** the cloud service offering. (Federal customer data = what an agency uploads/stores; excludes CSP-generated metadata/telemetry.)
- **Testability:** hybrid — the central MAS reconciliation.
- **Automated validation:** This is the anchor MAS cross-check. Take the operator's **documented in-scope IR set** (a config/inventory file in the tracker) and reconcile against **discovered inventory**: AWS Config Aggregator resource list (`inventory.ts` → `config.aggregators`/recorder) and GCP Cloud Asset Inventory (`cloudasset.assets.list`). Emit three buckets: (a) discovered-but-undocumented → potential boundary gap (in-scope resource not in the MAS doc); (b) documented-but-undiscovered → drift/decommissioned; (c) reconciled. The collector cannot decide "likely handles federal data" — that judgment is human — but it surfaces the candidate set for review. K8s adds workload inventory via the existing E.1 collector.
- **Required permissions & error handling:** AWS `config:Describe*`/`config:Get*` + `config:SelectAggregateResourceConfig`; GCP `roles/cloudasset.viewer` (`cloudasset.assets.list`). Both already wired in `inventory.ts`; AccessDenied → operator gets the exact action via `error-diagnostics.ts`.
- **Alternative satisfiers:** CSPM/CNAPP authoritative inventory (Wiz/Lacework) substituting for Config/Asset; attest its asset list as the discovery source.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a. (Maps conceptually to CM-8 inventory, but no `controls[]` provided to derive High.)
- **Module connections:** **new MAS reconciliation engine** built on `providers/{aws,gcp}/inventory.ts`; documented-set lives in tracker. This engine is reused by ADS-CSO-SVC, MAS-CSO-FLO, MAS-CSO-TPR, KSI-CSX-MAS.
- **Recommended implementation:** hybrid (inventory reconciliation collector + human scoping judgment); effort L — highest-value automation in the family.

### MAS-CSO-MDI — Metadata Inclusion  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST include metadata (including metadata *about* federal customer data) in the Minimum Assessment Scope **ONLY IF MAS-CSO-IIR APPLIES**.
- **Testability:** process-artifact (conditional scoping)
- **Automated validation:** None directly — it's a conditional inclusion rule. The tracker enforces dependency: if MAS-CSO-IIR is in scope (it is, for any CSO handling federal data), then the documented IR set MUST encompass relevant metadata stores. Weak corroboration: the IIR reconciliation can flag obvious metadata stores (e.g. CloudTrail/audit buckets, logging datasets) discovered but not documented — surface as candidates, since "metadata about federal customer data" vs excluded CSP telemetry is a definitional human call.
- **Required permissions & error handling:** n/a beyond the IIR inventory permissions.
- **Alternative satisfiers:** Same inventory tooling as IIR.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** MAS reconciliation engine (conditional gate keyed off MAS-CSO-IIR) + tracker.
- **Recommended implementation:** process-artifact-tracker (conditional rule on the IIR reconciliation); effort S.

### MAS-CSO-SUP — Supplemental Information  [MAY]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MAY include extra materials about IRs *not* part of the CSO in a package **supplement**; these won't be FedRAMP authorized and MUST be clearly marked and separated from the CSO.
- **Testability:** process-artifact
- **Automated validation:** None observable — a documentation-structure option. The embedded MUST ("clearly marked and separated") is a doc-review check, not environmental. Tracker holds the supplement (if any) and a marking/separation attestation.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** n/a (a MAY allowance).
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a.
- **Module connections:** new process-artifact tracker (optional supplement slot).
- **Recommended implementation:** process-artifact-tracker; effort S.

### MAS-CSO-TPR — Third-Party Information Resources  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** Providers MUST address the potential impact to federal customer data from *third-party information resources* (any IR not entirely inside the assessment) used by the CSO — **ONLY IF MAS-CSO-IIR APPLIES** — by documenting, for each: (1) general usage/configuration; (2) explanation/justification for use; (3) mitigation measures reducing impact to federal customer data; (4) compensating controls.
- **Testability:** hybrid
- **Automated validation:** Cross-check the documented third-party IR list against **detected** third parties: `core/detect/third-party-tools.ts` (Okta, Datadog, Snyk, Vault, etc. inferred from IAM/OIDC/SA signatures) and the subprocessor roster from `core/subprocessors-sheet.ts`. Flag detected third parties (subprocessors, external IdPs, SaaS integrations) **absent** from the documented TPR list → undocumented third-party exposure. The four documentation fields per resource are human-authored; the *completeness of the list* is what's automatable.
- **Required permissions & error handling:** reuses signals already gathered by IAM/OIDC collectors; subprocessor sheet read via `subprocessors-sheet.ts` (Google Sheets read). No new cloud permissions.
- **Alternative satisfiers:** GRC subprocessor/vendor register (Vanta/Drata vendor module) — attest its third-party inventory.
- **OSCAL / NIST:** controls[]=∅. High derived/pending; n/a. (Conceptually SA-9 external services, but no `controls[]` to derive High.)
- **Module connections:** MAS reconciliation engine + `core/detect/third-party-tools.ts` + `core/subprocessors-sheet.ts`; tracker for the per-resource documentation.
- **Recommended implementation:** hybrid (third-party detection cross-check + documentation artifact); effort M.

---

## Current state of KSI-CSX-SUM (`core/csx-sum-aggregator.ts`)

**What it already does (well):**
- Reads every `KSI-*.json` evidence file in `outDir` and emits one current-state markdown per KSI plus an aggregated `KSI-CSX-SUM-input.json` for Paramify / static-site rendering (matches the locked "markdown-in-git, no per-run snapshots" decision).
- Populates several of the six required summary fields automatically: **pass/fail criteria** (`pass_fail_criteria` = finding rule + severity), **consolidated resources** (`validated_resources_summary` from affected-resource counts / provider blocks), **current status** (`last_pass_status` + `last_run_at`), **validation module** name, NIST controls, related KSIs, and a failing-findings summary. Renders these into clean markdown.

**Gaps vs the FRMR requirement (the six MUST bullets):**
1. **Goals + traceability:** it lists pass/fail *criteria* (rule names) but no explicit per-KSI *goal* statement or traceability link back to the FRMR statement/NIST control as a "goal." Minor — could synthesize from `target_state.rationale`.
2. **Machine-based validation cycle:** `validation_cadence_days` is hardcoded to `1` with a TODO to read from `thresholds.yaml`. The requirement wants the *persistent cycle* per KSI (and Moderate needs ≤3-day machine validation). This should be driven by the level-selector / thresholds, not a constant.
3. **Non-machine-based validation processes:** **not represented at all.** The requirement explicitly wants the non-machine-based processes + their cycle (or an explanation of why N/A). Today there is no field for human/process validation — needs a tracker-sourced input merged in.
4. **Clarifications / responses to the assessment summary:** **not represented.** No field for assessor-response text — also a tracker-sourced human input.
5. **Consolidated-resource phrasing:** current summary is a count ("N affected resource(s)"), whereas the requirement's example is a semantic consolidation ("all employees with privileged access in the Admin group"). Improving this means pulling a human-readable resource-class label from findings rather than a raw count.

**Net:** the aggregator covers the *machine-derivable* ~3 of 6 fields; closing KSI-CSX-SUM needs (a) cadence driven by the level model instead of the `=1` constant, and (b) two new human-authored fields (non-machine-based processes, assessment clarifications) merged from the tracker. Effort to close: **M**, building on the existing module rather than replacing it.
