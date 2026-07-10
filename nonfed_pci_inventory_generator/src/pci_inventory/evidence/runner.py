"""Stage 3 orchestration: load → map evidence → follow-up findings → indicators →
build the consolidated evidence document.

Augments the Stage 2 artifact; never drops or alters prior records.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from pci_inventory.evidence.findings import FindingsResult, collect_findings
from pci_inventory.evidence.indicators import (
    INDICATOR_DISCLAIMER,
    Indicators,
    compute_indicators,
)
from pci_inventory.evidence.loader import LoadedArtifact, resource_scope
from pci_inventory.evidence.mapping import (
    COLUMN_REQUIREMENT_MAP,
    build_evidence_rows,
)
from pci_inventory.evidence.models import EvidenceRow, EvidenceThresholds

logger = logging.getLogger("pci_inventory.evidence.runner")

# Internet-facing LB resource types whose SSL ciphers F7 resolves (in-scope only).
_LB_TYPES = {"elbv2:application", "elbv2:network", "elbv2:load-balancer"}
_IN_SCOPE = ("CDE", "connected-to", "security-impacting")


@dataclass
class EvidenceResult:
    rows: list[EvidenceRow] = field(default_factory=list)
    findings: FindingsResult = field(default_factory=FindingsResult)
    indicators: Indicators = field(default_factory=Indicators)
    scope_missing: bool = False
    caveats: list[str] = field(default_factory=list)


def _in_scope_lb_arns(resources: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for r in resources:
        if r.get("resource_type") in _LB_TYPES and r.get("public_exposed") is True:
            cat = resource_scope(r)[0]
            if cat in _IN_SCOPE or cat == "undetermined":
                out.add(r.get("arn", ""))
    return out - {""}


def run_evidence(
    loaded: LoadedArtifact,
    thresholds: EvidenceThresholds,
    session_factory: Callable[[str], Any] | None = None,
    app_cfg: Any = None,
    reporter: Any = None,
) -> EvidenceResult:
    """Execute Stage 3 enrichment on a loaded artifact.

    ``reporter`` (optional :class:`~pci_inventory.progress.ProgressReporter`)
    drives the live UI: phase lines for the MAP/DERIVE steps and a live
    multi-worker dashboard over the parallel follow-up findings queries.
    """
    from pci_inventory.progress import ActivityTracker, ProgressReporter
    reporter = reporter or ProgressReporter(enabled=False, color=False)

    index = loaded.index
    resources = index.resources
    result = EvidenceResult(scope_missing=loaded.scope_missing)

    # 1. MAP — per-requirement evidence rows from already-collected inventory data.
    reporter.phase("Mapping evidence to requirements")
    for r in resources:
        result.rows.extend(build_evidence_rows(r))
    logger.info("Built %d evidence rows from %d resources", len(result.rows), len(resources))
    reporter.finish_phase(f"{len(result.rows)} evidence rows from {len(resources)} resources")

    # 2. FOLLOW-UP — bounded read-only findings queries (reuse Stage 1 infra).
    call_ctx, max_workers = _build_call_ctx(app_cfg)
    if call_ctx is not None and session_factory is not None:
        tracker = ActivityTracker()
        with reporter.worker_dashboard(
            tracker, call_ctx.errors, total=len(index.regions_in_use()),
            title="Follow-up security findings (F1–F8)",
            unit_noun="account-regions", record_noun="",
        ) as dash:
            result.findings = collect_findings(
                index, session_factory, call_ctx, max_workers,
                in_scope_lb_arns=_in_scope_lb_arns(resources),
                on_unit_start=dash.on_start, on_unit_end=dash.on_end,
                on_unit_done=dash.on_done)
            dash.set_summary(f"{len(result.findings.findings)} finding(s) collected")
    else:
        result.findings = collect_findings(
            index, session_factory, call_ctx, max_workers,
            in_scope_lb_arns=_in_scope_lb_arns(resources))
    # Attach findings to evidence rows by ARN.
    self_attach_findings(result)

    # 3. DERIVE — indicators overall + per scope.
    reporter.phase("Computing indicators")
    result.indicators = compute_indicators(resources, thresholds)
    reporter.finish_phase("indicators computed (NOT compliance determinations)")

    result.caveats = _caveats(loaded, result, thresholds)
    return result


def _build_call_ctx(app_cfg):
    if app_cfg is None:
        return None, 8
    from pci_inventory.concurrency import (
        CallContext,
        ErrorCollector,
        ServiceThrottleGate,
        TokenBucket,
    )
    cc = app_cfg.concurrency
    ctx = CallContext(
        TokenBucket(cc.tokens_per_second, cc.bucket_capacity),
        ServiceThrottleGate(cc.hard_throttle_services, cc.hard_throttle_cap, cc.medium_throttle_cap),
        ErrorCollector())
    return ctx, cc.max_workers


def self_attach_findings(result: EvidenceResult) -> None:
    """Attach security-service findings + SSL/WAF detail to evidence rows by ARN."""
    by_arn = result.findings.by_arn()
    ciphers = result.findings.ssl_policy_ciphers
    waf = result.findings.waf_associations
    for row in result.rows:
        fs = by_arn.get(row.resource_arn, [])
        for f in fs:
            row.findings.append(f"[{f.source}/{f.severity}] {f.title}")
        # Cipher detail is Req 4 evidence; WAF association is Req 6.
        if row.resource_arn in ciphers and row.requirement.short.startswith("Req 04"):
            row.fields["ssl_ciphers"] = ciphers[row.resource_arn]
        if row.resource_arn in waf and row.requirement.short.startswith("Req 06"):
            row.fields["waf_web_acl"] = waf[row.resource_arn]


def _caveats(loaded: LoadedArtifact, result: EvidenceResult,
             thresholds: EvidenceThresholds) -> list[str]:
    caveats = [
        INDICATOR_DISCLAIMER,
        "Read-only: this stage used only Describe/List/Get APIs (plus the standard "
        "GenerateCredentialReport idiom in Stage 1). No AWS resource was created, modified, or deleted.",
        "AUGMENT-ONLY: every Stage 1/2 record is preserved verbatim; this stage only adds an "
        "'evidence' block, indicators, and the requirement mapping.",
        "Shared responsibility: Requirement 9 (physical) and parts of Req 12 are AWS's responsibility "
        "(evidenced by AWS's PCI DSS Attestation via AWS Artifact) or are process/documentation "
        "controls not observable from AWS configuration.",
        "Not observable read-only (recorded as NOT_COLLECTABLE): in-guest anti-malware (Req 5), "
        "OS time-sync (Req 10.6), file-integrity monitoring (Req 11.5.2), and in-guest hardening (Req 2).",
        "Out-of-band: ASV external scans and penetration tests (Req 11.3/11.4) are not performed by "
        "this tool; it surfaces external scan targets (public endpoints) and segmentation config evidence.",
        f"Indicator thresholds (configurable): stale credential > {thresholds.stale_credential_days}d; "
        f"cert expiry warn < {thresholds.cert_expiry_warn_days}d / notice < {thresholds.cert_expiry_notice_days}d; "
        f"log retention < {thresholds.log_retention_min_days}d flagged (Req 10.5.1).",
    ]
    if result.scope_missing:
        caveats.insert(0,
            "⚠ SCOPE CONTEXT MISSING — Stage 2 (pci-inventory scope) was not run, so evidence is "
            "NOT prioritized by scope; every resource shows scope=undetermined. Run Stage 2 first "
            "for scope-classified evidence.")
    if result.findings.notes:
        caveats.append("Follow-up findings notes: " + "; ".join(result.findings.notes[:8]))
    return caveats


# --------------------------------------------------------------------------- #
# Consolidated evidence document (output/inventory-evidence.json)
# --------------------------------------------------------------------------- #
def build_evidence_document(loaded: LoadedArtifact, result: EvidenceResult) -> dict[str, Any]:
    """Build the final superset document (Stage 1/2 + per-resource evidence block)."""
    index = loaded.index
    doc = dict(index.document)
    doc["evidence_schema_version"] = "1.0.0"

    # Index evidence rows by resource ARN to attach an 'evidence' block per resource.
    rows_by_arn: dict[str, list[EvidenceRow]] = {}
    for row in result.rows:
        rows_by_arn.setdefault(row.resource_arn, []).append(row)
    findings_by_arn = result.findings.by_arn()

    enriched: list[dict[str, Any]] = []
    for r in index.resources:
        r2 = dict(r)  # preserve Stage 1/2 verbatim
        arn = r.get("arn", "")
        ev = {
            "by_requirement": {row.requirement.short: row.fields for row in rows_by_arn.get(arn, [])},
            "findings": [f.to_dict() for f in findings_by_arn.get(arn, [])],
        }
        r2["evidence"] = ev
        enriched.append(r2)
    doc["resources"] = enriched

    doc["evidence_analysis"] = {
        "scope_missing": result.scope_missing,
        "caveats": result.caveats,
        "indicators": result.indicators.to_dict(),
        "requirement_mapping": [
            {"data_point": dp, "requirements": req, "source": src}
            for dp, req, src in COLUMN_REQUIREMENT_MAP
        ],
        "findings": [f.to_dict() for f in result.findings.findings],
        "ssl_policy_ciphers": result.findings.ssl_policy_ciphers,
        "follow_up_notes": result.findings.notes,
        "evidence_row_count": len(result.rows),
    }
    return doc
