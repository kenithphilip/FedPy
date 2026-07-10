"""Security & crypto collectors: KMS (+ rotation/policy), CloudHSM, ACM (+ expiry),
Secrets Manager, SSM parameters (metadata only), GuardDuty, Security Hub,
Inspector2, Macie, Detective, Audit Manager.

Secret hygiene: SSM SecureString and Secrets Manager values are NEVER read — only
existence + metadata. KMS captures policy/rotation metadata, never key material.
"""

from __future__ import annotations

from typing import Any

from pci_inventory.collectors.base import (
    Collector,
    CollectorContext,
    collect_each,
    new_record,
    register,
    synth_arn,
    to_iso,
)
from pci_inventory.schema.models import ResourceRecord
from pci_inventory.utils import Sentinel, tags_to_dict, utc_now
from datetime import timezone


@register
class KMSCollector(Collector):
    service = "kms"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("kms")
        keys = ctx.call.paginate(client, "list_keys", account_id=ctx.account_id,
                                 region=ctx.region, service="kms", result_key="Keys")
        out: list[ResourceRecord] = []
        for k in keys:
            kid = k["KeyId"]
            desc = ctx.call.call(client.describe_key, account_id=ctx.account_id, region=ctx.region,
                                 service="kms", operation="DescribeKey", resource_id=kid, default=None,
                                 KeyId=kid)
            if not desc:
                continue
            meta = desc["KeyMetadata"]
            rec = new_record(ctx, service="kms", resource_type="kms:key",
                             resource_id=kid, arn=meta.get("Arn", ""))
            rec.creation_date = to_iso(meta.get("CreationDate"))
            rec.os_platform_engine = meta.get("KeySpec", meta.get("CustomerMasterKeySpec", ""))
            rec.description_purpose = meta.get("Description", "") or f"KMS key ({meta.get('KeyManager','')})"
            rec.encryption_at_rest = True
            mgr = meta.get("KeyManager", "")
            origin = meta.get("Origin", "")
            # R3: key origin/manager as a typed column.
            rec.key_origin_manager = {
                "AWS": "aws-managed", "CUSTOMER": "customer-managed",
            }.get(mgr, mgr.lower() or "unknown")
            if origin == "EXTERNAL":
                rec.key_origin_manager = "external"
            elif origin == "AWS_CLOUDHSM":
                rec.key_origin_manager = "cloudhsm"
            if meta.get("MultiRegion"):
                rec.add_note("multi-region key")
            rec.state_status = f"{meta.get('KeyState','')} ({mgr})"
            rec.source_calls = ["kms:ListKeys", "kms:DescribeKey"]

            symmetric = meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"
            # Rotation is only meaningful for customer-managed symmetric keys.
            if mgr == "CUSTOMER" and symmetric:
                rot = ctx.call.call(client.get_key_rotation_status, account_id=ctx.account_id,
                                    region=ctx.region, service="kms", operation="GetKeyRotationStatus",
                                    resource_id=kid, default={}, KeyId=kid)
                rec.kms_rotation_enabled = bool(rot.get("KeyRotationEnabled"))
                # R3: rotation period (v4 supports a custom interval).
                if rot.get("RotationPeriodInDays"):
                    rec.kms_rotation_period_days = str(rot["RotationPeriodInDays"])
                if not rot.get("KeyRotationEnabled"):
                    rec.add_note("key rotation disabled (review PCI 3.6.1/3.7.4)")
                rec.source_calls.append("kms:GetKeyRotationStatus")
                # Key policy → principals for the Stage 2 graph.
                pol = ctx.call.call(client.get_key_policy, account_id=ctx.account_id, region=ctx.region,
                                    service="kms", operation="GetKeyPolicy", resource_id=kid,
                                    default=None, KeyId=kid, PolicyName="default")
                if pol and pol.get("Policy"):
                    rec.iam_policy_data["key_policy"] = pol["Policy"]
                    rec.source_calls.append("kms:GetKeyPolicy")
            else:
                # Rotation N/A for asymmetric / AWS-managed keys — leave tri-bool None.
                rec.kms_rotation_period_days = Sentinel.NA

            rec.public_exposed = False
            out.append(rec)

        # Attach aliases to keys (one call).
        aliases = ctx.call.call(client.list_aliases, account_id=ctx.account_id, region=ctx.region,
                                service="kms", operation="ListAliases", default={"Aliases": []})
        alias_by_key: dict[str, list[str]] = {}
        for a in (aliases or {}).get("Aliases", []):
            if a.get("TargetKeyId"):
                alias_by_key.setdefault(a["TargetKeyId"], []).append(a.get("AliasName", ""))
        for rec in out:
            names = alias_by_key.get(rec.resource_id, [])
            if names:
                rec.add_relationship("aliases", names)
                if not rec.name:
                    rec.name = names[0]
        return out


@register
class CloudHSMCollector(Collector):
    service = "cloudhsm"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("cloudhsmv2")
        resp = ctx.call.call(client.describe_clusters, account_id=ctx.account_id, region=ctx.region,
                             service="cloudhsm", operation="DescribeClusters", default={"Clusters": []})
        out = []
        for c in resp.get("Clusters", []):
            rec = new_record(ctx, service="cloudhsm", resource_type="cloudhsm:cluster",
                             resource_id=c.get("ClusterId", ""),
                             arn=synth_arn("cloudhsm", ctx.region, ctx.account_id, f"cluster/{c.get('ClusterId','')}"))
            rec.state_status = c.get("State", "")
            rec.creation_date = to_iso(c.get("CreateTimestamp"))
            rec.os_platform_engine = c.get("HsmType", "")
            rec.description_purpose = "CloudHSM cluster (dedicated key store)"
            rec.encryption_at_rest = True
            rec.add_relationship("vpc", c.get("VpcId"))
            rec.public_exposed = False
            rec.source_calls = ["cloudhsmv2:DescribeClusters"]
            out.append(rec)
        return out


@register
class ACMCollector(Collector):
    service = "acm"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("acm")
        certs = ctx.call.paginate(client, "list_certificates", account_id=ctx.account_id,
                                  region=ctx.region, service="acm", result_key="CertificateSummaryList")
        out = []
        for summary in certs:
            arn = summary["CertificateArn"]
            desc = ctx.call.call(client.describe_certificate, account_id=ctx.account_id, region=ctx.region,
                                 service="acm", operation="DescribeCertificate", resource_id=arn,
                                 default=None, CertificateArn=arn)
            c = (desc or {}).get("Certificate", summary)
            rec = new_record(ctx, service="acm", resource_type="acm:certificate",
                             resource_id=arn.split("/")[-1], arn=arn, name=c.get("DomainName", ""))
            rec.state_status = c.get("Status", "")
            rec.creation_date = to_iso(c.get("CreatedAt"))
            rec.dns_names = [c.get("DomainName", "")] + c.get("SubjectAlternativeNames", [])
            rec.dns_names = sorted(set(d for d in rec.dns_names if d))
            not_after = c.get("NotAfter")
            rec.last_modified_activity = to_iso(not_after)
            rec.encryption_in_transit = True
            rec.description_purpose = f"ACM certificate for {c.get('DomainName','')}"
            # R2/R3: typed cert columns (expiry, key algorithm).
            rec.cert_expiry_date = to_iso(not_after)
            algo = c.get("KeyAlgorithm", "")  # e.g. RSA_2048, EC_prime256v1
            rec.cert_key_algo = algo.replace("_", "-") if algo else Sentinel.NA
            rec.cert_key_algo = rec.cert_key_algo  # keep as-is for QSA readability
            # Renewal + type metadata as a note (Req 4.2.1.1).
            rtype = c.get("Type", "")
            renew = c.get("RenewalEligibility", "")
            if not_after:
                try:
                    days = (not_after.astimezone(timezone.utc) - utc_now()).days
                    rec.backup_config = f"expires in {days} days; type={rtype}; renewal={renew}"
                    if days < 30:
                        rec.add_note(f"certificate expires in {days} days (review 4.2.1.1)")
                    if rtype == "IMPORTED" and renew != "ELIGIBLE":
                        rec.add_note("imported cert — not auto-renewing")
                except Exception:  # noqa: BLE001
                    pass
            rec.add_relationship("in_use_by", c.get("InUseBy", []))
            rec.public_exposed = False
            rec.source_calls = ["acm:ListCertificates", "acm:DescribeCertificate"]
            out.append(rec)
        return out


@register
class SecretsManagerCollector(Collector):
    service = "secretsmanager"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("secretsmanager")
        secrets = ctx.call.paginate(client, "list_secrets", account_id=ctx.account_id,
                                    region=ctx.region, service="secretsmanager", result_key="SecretList")
        out = []
        for s in secrets:
            arn = s["ARN"]
            rec = new_record(ctx, service="secretsmanager", resource_type="secretsmanager:secret",
                             resource_id=s.get("Name", arn), arn=arn, name=s.get("Name", ""))
            rec.tags = tags_to_dict(s.get("Tags"))
            rec.creation_date = to_iso(s.get("CreatedDate"))
            rec.last_modified_activity = to_iso(s.get("LastChangedDate") or s.get("LastAccessedDate"))
            rec.description_purpose = s.get("Description", "") or "Secrets Manager secret (metadata only)"
            rec.encryption_at_rest = True
            if s.get("KmsKeyId"):
                rec.add_relationship("kms_key", s["KmsKeyId"])
            rec.backup_config = f"rotation={'enabled' if s.get('RotationEnabled') else 'disabled'}"
            # Resource policy (existence) for Stage 2 graph — never the value.
            pol = ctx.call.call(client.get_resource_policy, account_id=ctx.account_id, region=ctx.region,
                                service="secretsmanager", operation="GetResourcePolicy", resource_id=arn,
                                default=None, SecretId=arn)
            if pol and pol.get("ResourcePolicy"):
                rec.iam_policy_data["resource_based_policy"] = pol["ResourcePolicy"]
            rec.public_exposed = False
            rec.source_calls = ["secretsmanager:ListSecrets", "secretsmanager:GetResourcePolicy"]
            out.append(rec)
        return out


@register
class SSMParameterCollector(Collector):
    service = "ssm"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ssm")
        params = ctx.call.paginate(client, "describe_parameters", account_id=ctx.account_id,
                                   region=ctx.region, service="ssm", result_key="Parameters")
        # NOTE: describe_parameters returns metadata only — values are never fetched.
        return collect_each(params, lambda p: self._build(ctx, p))

    def _build(self, ctx: CollectorContext, p: dict[str, Any]) -> ResourceRecord:
        name = p["Name"]
        arn = synth_arn("ssm", ctx.region, ctx.account_id, f"parameter{name if name.startswith('/') else '/' + name}")
        rec = new_record(ctx, service="ssm", resource_type="ssm:parameter",
                         resource_id=name, arn=arn, name=name)
        rec.last_modified_activity = to_iso(p.get("LastModifiedDate"))
        ptype = p.get("Type", "")
        rec.os_platform_engine = ptype
        rec.encryption_at_rest = ptype == "SecureString"
        rec.description_purpose = (p.get("Description", "")
                                   or f"SSM {ptype} parameter (metadata only; value not read)")
        if p.get("KeyId"):
            rec.add_relationship("kms_key", p["KeyId"])
        rec.public_exposed = False
        rec.source_calls = ["ssm:DescribeParameters"]
        return rec


@register
class SecurityServicesCollector(Collector):
    """GuardDuty, Security Hub, Inspector2, Macie, Detective, Audit Manager status."""

    service = "guardduty"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        out += self._guardduty(ctx)
        out += self._securityhub(ctx)
        out += self._inspector(ctx)
        out += self._macie(ctx)
        out += self._detective(ctx)
        return out

    def _guardduty(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("guardduty")
        det = ctx.call.call(client.list_detectors, account_id=ctx.account_id, region=ctx.region,
                            service="guardduty", operation="ListDetectors", default={"DetectorIds": []})
        out = []
        for did in det.get("DetectorIds", []):
            info = ctx.call.call(client.get_detector, account_id=ctx.account_id, region=ctx.region,
                                 service="guardduty", operation="GetDetector", resource_id=did,
                                 default={}, DetectorId=did)
            rec = new_record(ctx, service="guardduty", resource_type="guardduty:detector",
                             resource_id=did, arn=synth_arn("guardduty", ctx.region, ctx.account_id, f"detector/{did}"))
            rec.state_status = info.get("Status", "")
            rec.logging_enabled = info.get("Status") == "ENABLED"
            rec.description_purpose = "GuardDuty detector (threat detection)"
            # R3: high/critical finding count (Req 11 threat detection signal).
            stats = ctx.call.call(client.get_findings_statistics, account_id=ctx.account_id, region=ctx.region,
                                  service="guardduty", operation="GetFindingsStatistics", resource_id=did,
                                  default=None, DetectorId=did, FindingStatisticTypes=["COUNT_BY_SEVERITY"])
            if stats:
                by_sev = stats.get("FindingStatistics", {}).get("CountBySeverity", {})
                # GuardDuty severities: 7.0-8.9 High, >=9 Critical, 4-6.9 Medium.
                high = sum(v for k, v in by_sev.items() if float(k) >= 7.0)
                rec.vuln_findings_summary = f"high+critical={high} total={sum(by_sev.values())}"
                if high:
                    rec.add_note(f"{high} high/critical GuardDuty findings (review 11.x)")
                rec.source_calls = ["guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:GetFindingsStatistics"]
            else:
                rec.source_calls = ["guardduty:ListDetectors", "guardduty:GetDetector"]
            rec.public_exposed = False
            out.append(rec)
        return out

    def _securityhub(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("securityhub")
        hub = ctx.call.call(client.describe_hub, account_id=ctx.account_id, region=ctx.region,
                            service="securityhub", operation="DescribeHub", default=None)
        if not hub:
            return []
        rec = new_record(ctx, service="securityhub", resource_type="securityhub:hub",
                         resource_id="security-hub", arn=hub.get("HubArn", ""))
        rec.state_status = "enabled"
        rec.logging_enabled = True
        rec.creation_date = to_iso(hub.get("SubscribedAt"))
        rec.description_purpose = "Security Hub (posture management)"
        std = ctx.call.call(client.get_enabled_standards, account_id=ctx.account_id, region=ctx.region,
                            service="securityhub", operation="GetEnabledStandards", default={"StandardsSubscriptions": []})
        names = [s.get("StandardsArn", "").split("/")[-3] if "/" in s.get("StandardsArn", "") else s.get("StandardsArn", "")
                 for s in (std or {}).get("StandardsSubscriptions", [])]
        rec.notes = "standards: " + ", ".join(n for n in names if n)
        rec.public_exposed = False
        rec.source_calls = ["securityhub:DescribeHub", "securityhub:GetEnabledStandards"]
        return [rec]

    def _inspector(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("inspector2")
        status = ctx.call.call(client.batch_get_account_status, account_id=ctx.account_id, region=ctx.region,
                               service="inspector2", operation="BatchGetAccountStatus", default=None)
        if not status:
            return []
        out = []
        for acct in status.get("accounts", []):
            rec = new_record(ctx, service="inspector2", resource_type="inspector2:account-status",
                             resource_id=acct.get("accountId", ctx.account_id),
                             arn=synth_arn("inspector2", ctx.region, ctx.account_id, "account-status"))
            state = acct.get("state", {}).get("status", "")
            rec.state_status = state
            rec.logging_enabled = state == "ENABLED"
            rec.vuln_scan_status = "enabled" if state == "ENABLED" else "disabled"
            rec.description_purpose = "Inspector v2 (vulnerability scanning)"
            rec.source_calls = ["inspector2:BatchGetAccountStatus"]
            # R3: open finding counts by severity (Req 6.3.1/11.3.1).
            if state == "ENABLED":
                counts = ctx.call.call(client.list_finding_aggregations, account_id=ctx.account_id,
                                       region=ctx.region, service="inspector2",
                                       operation="ListFindingAggregations", default=None,
                                       aggregationType="ACCOUNT")
                if counts and counts.get("responses"):
                    sev = counts["responses"][0].get("accountAggregation", {}).get("severityCounts", {})
                    rec.vuln_findings_summary = (f"crit={sev.get('critical',0)} high={sev.get('high',0)} "
                                                 f"med={sev.get('medium',0)}")
                    if sev.get("critical") or sev.get("high"):
                        rec.add_note("open critical/high Inspector findings (review 6.3.1/11.3.1)")
                    rec.source_calls.append("inspector2:ListFindingAggregations")
            rec.public_exposed = False
            out.append(rec)
        return out

    def _macie(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("macie2")
        sess = ctx.call.call(client.get_macie_session, account_id=ctx.account_id, region=ctx.region,
                             service="macie2", operation="GetMacieSession", default=None)
        if not sess:
            return []
        rec = new_record(ctx, service="macie2", resource_type="macie2:session",
                         resource_id="macie", arn=synth_arn("macie2", ctx.region, ctx.account_id, "session"))
        rec.state_status = sess.get("status", "")
        rec.logging_enabled = sess.get("status") == "ENABLED"
        rec.creation_date = to_iso(sess.get("createdAt"))
        rec.description_purpose = "Macie (sensitive data discovery)"
        rec.public_exposed = False
        rec.source_calls = ["macie2:GetMacieSession"]
        return [rec]

    def _detective(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("detective")
        graphs = ctx.call.paginate(client, "list_graphs", account_id=ctx.account_id,
                                   region=ctx.region, service="detective", result_key="GraphList")
        out = []
        for g in graphs:
            rec = new_record(ctx, service="detective", resource_type="detective:graph",
                             resource_id=g.get("Arn", "").split("/")[-1], arn=g.get("Arn", ""))
            rec.creation_date = to_iso(g.get("CreatedTime"))
            rec.description_purpose = "Detective behavior graph"
            rec.public_exposed = False
            rec.source_calls = ["detective:ListGraphs"]
            out.append(rec)
        return out
