"""Derived indicators — tool aids to assist a QSA, NOT compliance determinations.

Computed from the enriched artifact: coverage percentages and risk lists, each
**overall and broken down by scope category** (the in-scope subset is what a QSA
prioritizes). Thresholds are conventional, configurable, and labelled as
indicators. Every output here is explicitly non-determinative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pci_inventory.evidence.loader import resource_scope
from pci_inventory.evidence.models import IN_SCOPE_CATEGORIES, EvidenceThresholds

# Loud disclaimer attached to the indicators block + sheet.
INDICATOR_DISCLAIMER = (
    "These are tool-collected INDICATORS to assist assessment — NOT compliance "
    "determinations. A passing indicator does not prove a requirement is met; a "
    "failing indicator is evidence warranting review. The QSA makes all determinations."
)


def _pct(num: int, denom: int) -> float | None:
    return round(100.0 * num / denom, 1) if denom else None


def _age_int(value: Any) -> int | None:
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


@dataclass
class Indicators:
    overall: dict[str, Any] = field(default_factory=dict)
    by_scope: dict[str, dict[str, Any]] = field(default_factory=dict)
    risk_lists: dict[str, list[str]] = field(default_factory=dict)
    disclaimer: str = INDICATOR_DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return {
            "disclaimer": self.disclaimer,
            "overall": self.overall,
            "by_scope": self.by_scope,
            "risk_lists": self.risk_lists,
        }


def _coverage_block(resources: list[dict[str, Any]]) -> dict[str, Any]:
    """Coverage %s + counts for one resource subset."""
    enc_applicable = [r for r in resources if r.get("encryption_at_rest") in (True, False)]
    enc_yes = [r for r in enc_applicable if r.get("encryption_at_rest") is True]
    tls_applicable = [r for r in resources if r.get("encryption_in_transit") in (True, False)]
    tls_yes = [r for r in tls_applicable if r.get("encryption_in_transit") is True]
    instances = [r for r in resources if r.get("resource_type") == "ec2:instance"]
    imdsv2_yes = [r for r in instances if r.get("imdsv2_required") is True]
    mfa_applicable = [r for r in resources
                      if r.get("resource_type") in ("iam:user", "iam:account-settings")
                      and r.get("mfa_enabled") in (True, False)]
    mfa_yes = [r for r in mfa_applicable if r.get("mfa_enabled") is True]
    return {
        "resource_count": len(resources),
        "encryption_at_rest_pct": _pct(len(enc_yes), len(enc_applicable)),
        "encryption_at_rest_applicable": len(enc_applicable),
        "encryption_in_transit_pct": _pct(len(tls_yes), len(tls_applicable)),
        "encryption_in_transit_applicable": len(tls_applicable),
        "imdsv2_enforcement_pct": _pct(len(imdsv2_yes), len(instances)),
        "ec2_instance_count": len(instances),
        "mfa_coverage_pct": _pct(len(mfa_yes), len(mfa_applicable)),
        "mfa_applicable": len(mfa_applicable),
        "public_exposed_count": sum(1 for r in resources if r.get("public_exposed") is True),
        "unencrypted_count": sum(1 for r in resources if r.get("encryption_at_rest") is False),
        "patch_non_compliant_count": sum(1 for r in resources
                                         if r.get("patch_compliance") == "NON_COMPLIANT"),
    }


def compute_indicators(resources: list[dict[str, Any]],
                       thresholds: EvidenceThresholds) -> Indicators:
    """Compute all derived indicators overall + per scope category."""
    ind = Indicators()
    ind.overall = _coverage_block(resources)

    # Per-scope breakdown (in-scope categories the QSA prioritizes).
    def cat_of(r):
        return resource_scope(r)[0]
    for category in IN_SCOPE_CATEGORIES + ("out-of-scope", "undetermined"):
        subset = [r for r in resources if cat_of(r) == category]
        if subset:
            ind.by_scope[category] = _coverage_block(subset)

    # --- risk lists (resource ARNs/labels) ---
    risk: dict[str, list[str]] = {}

    risk["public_exposed"] = sorted(
        f"{r.get('arn')} [{cat_of(r)}]" for r in resources if r.get("public_exposed") is True)
    risk["unencrypted_at_rest"] = sorted(
        f"{r.get('arn')} [{cat_of(r)}]" for r in resources if r.get("encryption_at_rest") is False)
    risk["publicly_shared"] = sorted(
        f"{r.get('arn')} [{cat_of(r)}]" for r in resources if r.get("publicly_shared") is True)

    # Stale credentials: access-key age or last-used beyond threshold.
    stale = []
    for r in resources:
        if r.get("resource_type") not in ("iam:user", "iam:role"):
            continue
        ak = _age_int(r.get("access_key_age_days"))
        lu = _age_int(r.get("last_used_age_days"))
        flags = []
        if ak is not None and ak > thresholds.stale_credential_days:
            flags.append(f"key-age={ak}d")
        if lu is not None and lu > thresholds.stale_credential_days:
            flags.append(f"last-used={lu}d")
        if flags:
            stale.append(f"{r.get('arn')} ({', '.join(flags)})")
    risk["stale_credentials"] = sorted(stale)

    # Certs/keys nearing expiry + KMS rotation disabled.
    expiring = []
    for r in resources:
        exp = r.get("cert_expiry_date", "")
        if exp:
            days = _days_until(exp)
            if days is not None and days <= thresholds.cert_expiry_notice_days:
                tier = "WARN" if days <= thresholds.cert_expiry_warn_days else "notice"
                expiring.append(f"{r.get('arn')} expires in {days}d [{tier}]")
        if r.get("resource_type") == "kms:key" and r.get("kms_rotation_enabled") is False:
            expiring.append(f"{r.get('arn')} KMS rotation disabled")
    risk["certs_keys_attention"] = sorted(expiring)

    # Log groups below retention threshold.
    short_logs = []
    for r in resources:
        if r.get("resource_type") == "logs:log-group":
            ret = _age_int(r.get("log_retention_days"))
            if ret is not None and ret < thresholds.log_retention_min_days:
                short_logs.append(f"{r.get('arn')} retention={ret}d (<{thresholds.log_retention_min_days})")
    risk["log_retention_below_threshold"] = sorted(short_logs)

    # Overly-permissive IAM (wildcards / admin / open trust) from iam_policy_data.
    overly = []
    for r in resources:
        if not r.get("resource_type", "").startswith("iam:"):
            continue
        ipd = r.get("iam_policy_data", {}) or {}
        trust = ipd.get("trust_principals", []) or []
        if "*" in [str(p) for p in trust]:
            overly.append(f"{r.get('arn')} (trusts *)")
        managed = ipd.get("attached_managed_policies", []) or []
        if any("AdministratorAccess" in str(m) for m in managed):
            overly.append(f"{r.get('arn')} (AdministratorAccess attached)")
    risk["overly_permissive_iam"] = sorted(set(overly))

    # CloudTrail / Config coverage (account-level booleans).
    trails = [r for r in resources if r.get("resource_type") == "cloudtrail:trail"]
    multi_region_logging = any("multi_region=True" in (t.get("state_status", "") or "") and
                               t.get("logging_enabled") is True for t in trails)
    config_recorders = [r for r in resources if r.get("resource_type") == "config:recorder"]
    config_recording = any(r.get("logging_enabled") is True for r in config_recorders)
    ind.overall["cloudtrail_multiregion_logging"] = "Yes" if multi_region_logging else "No"
    ind.overall["config_recording_present"] = "Yes" if config_recording else "No"

    ind.risk_lists = risk
    return ind


def _days_until(iso_utc: str) -> int | None:
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(iso_utc.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except (ValueError, TypeError):
        return None
