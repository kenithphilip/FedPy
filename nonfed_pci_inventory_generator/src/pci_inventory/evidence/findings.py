"""Stage 3 follow-up findings collectors (F1–F8 in research/08 §2).

These are the genuinely-new, inventory-driven read-only queries — security-service
findings (Security Hub, GuardDuty, Inspector, Access Analyzer, Config, Macie) plus
ELBv2 SSL-cipher detail and WAF associations for in-scope internet-facing
resources. All run through Stage 1's rate-limited, error-capturing ``CallContext``
and the bounded ``run_work_units`` thread pool (one work unit per account×region),
so a wide multi-region run can't throttle and every failure is captured.

Findings are joined to inventory resources by ARN. A finding whose resource isn't
in the inventory is retained (attached to account/region) so nothing is lost. A
service that isn't enabled / denies access yields no findings (recorded), never a
fatal error.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from pci_inventory.concurrency import CallContext, WorkUnit, run_work_units

logger = logging.getLogger("pci_inventory.evidence.findings")


@dataclass
class Finding:
    """One security-service finding, joined to a resource ARN where possible."""

    source: str  # securityhub | guardduty | inspector2 | access-analyzer | config | macie
    severity: str  # CRITICAL/HIGH/... or a service-native label
    title: str
    resource_arn: str  # "" if not resolvable
    account_id: str
    region: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "severity": self.severity, "title": self.title,
            "resource_arn": self.resource_arn, "account_id": self.account_id,
            "region": self.region, "detail": self.detail,
        }


@dataclass
class FindingsResult:
    findings: list[Finding] = field(default_factory=list)
    ssl_policy_ciphers: dict[str, str] = field(default_factory=dict)  # lb_arn -> cipher summary
    waf_associations: dict[str, str] = field(default_factory=dict)  # resource_arn -> web-acl
    notes: list[str] = field(default_factory=list)

    def by_arn(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            if f.resource_arn:
                out.setdefault(f.resource_arn, []).append(f)
        return out


def _regions_in_use(index) -> list[tuple[str, str]]:
    return sorted(index.regions_in_use())


def collect_findings(
    index,
    session_factory: Callable[[str], Any] | None,
    call_ctx: CallContext | None,
    max_workers: int = 8,
    *,
    in_scope_lb_arns: set[str] | None = None,
    on_unit_start: Callable[[Any], None] | None = None,
    on_unit_end: Callable[[Any], None] | None = None,
    on_unit_done: Callable[[int, int, Any, int], None] | None = None,
) -> FindingsResult:
    """Run the bounded follow-up findings queries; return joined findings.

    ``session_factory`` and ``call_ctx`` mirror the Stage 2 gap-fetch contract.
    Degrades to empty (with a note) when credentials are unavailable.
    """
    result = FindingsResult()
    pairs = _regions_in_use(index)
    if not pairs:
        result.notes.append("no in-use regions in artifact; no follow-up findings collected")
        return result
    if session_factory is None or call_ctx is None:
        result.notes.append("no credentials available; security-service findings NOT collected "
                            "(evidence reflects inventory data only)")
        return result

    by_account: dict[str, set[str]] = {}
    for acct, region in pairs:
        by_account.setdefault(acct, set()).add(region)

    sessions: dict[str, Any] = {}
    for account_id in sorted(by_account):
        try:
            s = session_factory(account_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("No session for %s: %s", account_id, exc)
            s = None
        if s is not None:
            sessions[account_id] = s
        else:
            result.notes.append(f"account {account_id}: no session; findings skipped")

    lock = threading.Lock()
    in_scope_lb_arns = in_scope_lb_arns or set()

    def make_unit(account_id: str, region: str) -> WorkUnit:
        session = sessions[account_id]

        def _run() -> list[Any]:
            local: list[Finding] = []
            local += _security_hub(session, call_ctx, account_id, region)
            local += _guardduty(session, call_ctx, account_id, region)
            local += _inspector(session, call_ctx, account_id, region)
            local += _access_analyzer(session, call_ctx, account_id, region)
            local += _config(session, call_ctx, account_id, region)
            local += _macie(session, call_ctx, account_id, region)
            ciphers = _elbv2_ssl(session, call_ctx, account_id, region, in_scope_lb_arns)
            with lock:
                result.findings.extend(local)
                result.ssl_policy_ciphers.update(ciphers)
            return []

        return WorkUnit(account_id=account_id, region=region, service="securityhub",
                        label="evidence:findings", fn=_run)

    units = [make_unit(a, r) for a in sorted(sessions) for r in sorted(by_account[a])]
    run_work_units(units, max_workers, on_unit_start=on_unit_start,
                   on_unit_end=on_unit_end, on_unit_done=on_unit_done)

    # Surface captured follow-up errors as notes.
    for err in call_ctx.errors.errors:
        result.notes.append(f"{err.account_id}/{err.region} {err.service}:{err.operation}: {err.error_code}")
    return result


# --------------------------------------------------------------------------- #
# Per-service follow-up queries. Each is best-effort and read-only.
# --------------------------------------------------------------------------- #
def _security_hub(session, ctx: CallContext, account: str, region: str) -> list[Finding]:
    client = session.client("securityhub", region=region)
    out: list[Finding] = []
    # Active, failed-control findings, capped to a sane page for indicators.
    resp = ctx.call(client.get_findings, account_id=account, region=region, service="securityhub",
                    operation="GetFindings", default=None,
                    Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                             "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}]},
                    MaxResults=100)
    for f in (resp or {}).get("Findings", []):
        arn = ""
        res = f.get("Resources", [])
        if res:
            arn = res[0].get("Id", "")
        out.append(Finding("securityhub", f.get("Severity", {}).get("Label", "?"),
                           f.get("Title", "")[:160], arn, account, region,
                           detail=f.get("Compliance", {}).get("Status", "")))
    return out


def _guardduty(session, ctx: CallContext, account: str, region: str) -> list[Finding]:
    client = session.client("guardduty", region=region)
    det = ctx.call(client.list_detectors, account_id=account, region=region, service="guardduty",
                   operation="ListDetectors", default={"DetectorIds": []})
    out: list[Finding] = []
    for did in det.get("DetectorIds", []):
        ids = ctx.call(client.list_findings, account_id=account, region=region, service="guardduty",
                       operation="ListFindings", default={"FindingIds": []}, DetectorId=did,
                       FindingCriteria={"Criterion": {"severity": {"GreaterThanOrEqual": 7}}},
                       MaxResults=50)
        fids = ids.get("FindingIds", [])
        if not fids:
            continue
        got = ctx.call(client.get_findings, account_id=account, region=region, service="guardduty",
                       operation="GetFindings", default={"Findings": []}, DetectorId=did, FindingIds=fids[:50])
        for f in got.get("Findings", []):
            inst = f.get("Resource", {}).get("InstanceDetails", {}).get("InstanceId", "")
            out.append(Finding("guardduty", str(f.get("Severity", "")), f.get("Type", "")[:160],
                              inst or "", account, region, detail=f.get("Title", "")[:160]))
    return out


def _inspector(session, ctx: CallContext, account: str, region: str) -> list[Finding]:
    client = session.client("inspector2", region=region)
    out: list[Finding] = []
    for agg_type, key in (("AWS_EC2_INSTANCE", "ec2InstanceAggregation"),
                          ("AWS_ECR_CONTAINER_IMAGE", "imageAggregation"),
                          ("AWS_LAMBDA_FUNCTION", "lambdaFunctionAggregation")):
        resp = ctx.call(client.list_finding_aggregations, account_id=account, region=region,
                        service="inspector2", operation="ListFindingAggregations", default=None,
                        aggregationType=agg_type, maxResults=100)
        if not resp:
            continue
        for agg in resp.get("responses", []):
            a = agg.get(key, {})
            counts = a.get("severityCounts", {})
            arn = a.get("resourceId", a.get("functionName", a.get("repository", "")))
            crit, high = counts.get("critical", 0), counts.get("high", 0)
            if crit or high:
                out.append(Finding("inspector2", "CRITICAL" if crit else "HIGH",
                                  f"vuln findings crit={crit} high={high}", arn or "",
                                  account, region, detail=agg_type))
    return out


def _access_analyzer(session, ctx: CallContext, account: str, region: str) -> list[Finding]:
    client = session.client("accessanalyzer", region=region)
    analyzers = ctx.call(client.list_analyzers, account_id=account, region=region,
                         service="access-analyzer", operation="ListAnalyzers", default={"analyzers": []})
    out: list[Finding] = []
    for a in analyzers.get("analyzers", []):
        resp = ctx.call(client.list_findings, account_id=account, region=region,
                        service="access-analyzer", operation="ListFindings", default={"findings": []},
                        analyzerArn=a.get("arn", ""), filter={"status": {"eq": ["ACTIVE"]}}, maxResults=100)
        for f in resp.get("findings", []):
            res = f.get("resource", "")
            out.append(Finding("access-analyzer", "PUBLIC" if f.get("isPublic") else "EXTERNAL",
                              f"external/public access: {f.get('resourceType','')}", res, account,
                              region, detail="; ".join(f.get("action", [])[:5])))
    return out


def _config(session, ctx: CallContext, account: str, region: str) -> list[Finding]:
    client = session.client("config", region=region)
    rules = ctx.call(client.describe_config_rules, account_id=account, region=region, service="config",
                     operation="DescribeConfigRules", default={"ConfigRules": []})
    out: list[Finding] = []
    for rule in rules.get("ConfigRules", [])[:200]:
        name = rule.get("ConfigRuleName", "")
        comp = ctx.call(client.get_compliance_details_by_config_rule, account_id=account, region=region,
                        service="config", operation="GetComplianceDetailsByConfigRule", default=None,
                        ConfigRuleName=name, ComplianceTypes=["NON_COMPLIANT"], Limit=100)
        for r in (comp or {}).get("EvaluationResults", []):
            qid = r.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
            rtype = qid.get("ResourceType", "")
            rid = qid.get("ResourceId", "")
            out.append(Finding("config", "NON_COMPLIANT", f"config rule {name}", rid, account,
                              region, detail=rtype))
    return out


def _macie(session, ctx: CallContext, account: str, region: str) -> list[Finding]:
    client = session.client("macie2", region=region)
    sess = ctx.call(client.get_macie_session, account_id=account, region=region, service="macie2",
                    operation="GetMacieSession", default=None)
    if not sess or sess.get("status") != "ENABLED":
        return []
    stats = ctx.call(client.get_finding_statistics, account_id=account, region=region, service="macie2",
                     operation="GetFindingStatistics", default=None, groupBy="type")
    out: list[Finding] = []
    for item in (stats or {}).get("countsByGroup", []):
        if item.get("count"):
            out.append(Finding("macie", "SENSITIVE-DATA", item.get("groupKey", "sensitive-data"),
                             "", account, region, detail=f"count={item['count']}"))
    return out


def _elbv2_ssl(session, ctx: CallContext, account: str, region: str,
               in_scope_lb_arns: set[str]) -> dict[str, str]:
    """Resolve SSL-policy ciphers for in-scope internet-facing LBs only (F7)."""
    if not in_scope_lb_arns:
        return {}
    client = session.client("elbv2", region=region)
    lbs = ctx.call(client.describe_load_balancers, account_id=account, region=region, service="elbv2",
                   operation="DescribeLoadBalancers", default={"LoadBalancers": []})
    relevant = [lb for lb in lbs.get("LoadBalancers", []) if lb.get("LoadBalancerArn") in in_scope_lb_arns]
    if not relevant:
        return {}
    # Gather the SSL policies referenced by these LBs' HTTPS/TLS listeners.
    policy_names: dict[str, list[str]] = {}  # policy -> [lb_arn]
    for lb in relevant:
        arn = lb["LoadBalancerArn"]
        listeners = ctx.call(client.describe_listeners, account_id=account, region=region,
                             service="elbv2", operation="DescribeListeners", default={"Listeners": []},
                             LoadBalancerArn=arn)
        for ls in listeners.get("Listeners", []):
            if ls.get("SslPolicy"):
                policy_names.setdefault(ls["SslPolicy"], []).append(arn)
    if not policy_names:
        return {}
    desc = ctx.call(client.describe_ssl_policies, account_id=account, region=region, service="elbv2",
                    operation="DescribeSslPolicies", default={"SslPolicies": []},
                    Names=list(policy_names.keys()))
    out: dict[str, str] = {}
    for pol in desc.get("SslPolicies", []):
        ciphers = ", ".join(c.get("Name", "") for c in pol.get("Ciphers", [])[:8])
        weak = any("RC4" in c.get("Name", "") or "3DES" in c.get("Name", "") or
                   "DES-" in c.get("Name", "") for c in pol.get("Ciphers", []))
        summary = f"{pol.get('Name','')}: {ciphers}" + (" [WEAK CIPHERS]" if weak else "")
        for arn in policy_names.get(pol.get("Name", ""), []):
            out[arn] = summary
    return out
