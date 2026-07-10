"""Management / Org collectors (mostly GLOBAL): Organizations accounts/OUs/SCPs,
Control Tower, Trusted Advisor (Business+ support), Health.

Organizations data is only available from a management or delegated-admin
account; AccessDenied elsewhere is captured (not fatal). Trusted Advisor and
Health require Business/Enterprise Support; otherwise recorded as NOT_COLLECTED.
"""

from __future__ import annotations

from typing import Any

from pci_inventory.collectors.base import (
    Collector,
    CollectorContext,
    new_record,
    register,
    to_iso,
)
from pci_inventory.schema.models import ResourceRecord
from pci_inventory.utils import GLOBAL_REGION


@register
class OrganizationsCollector(Collector):
    service = "organizations"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("organizations", region=None)
        out: list[ResourceRecord] = []

        org = ctx.call.call(client.describe_organization, account_id=ctx.account_id, region=GLOBAL_REGION,
                            service="organizations", operation="DescribeOrganization", default=None)
        if not org:
            # Not an org management/member with access — nothing to collect.
            return out
        o = org.get("Organization", {})
        rec = new_record(ctx, service="organizations", resource_type="organizations:organization",
                         resource_id=o.get("Id", ""), arn=o.get("Arn", ""), region=GLOBAL_REGION,
                         name=o.get("Id", ""))
        rec.description_purpose = f"AWS Organization (master={o.get('MasterAccountId','')})"
        rec.state_status = o.get("FeatureSet", "")
        rec.add_relationship("master_account", o.get("MasterAccountId"))
        rec.public_exposed = False
        rec.source_calls = ["organizations:DescribeOrganization"]
        out.append(rec)

        # Member accounts.
        for acct in ctx.call.paginate(client, "list_accounts", account_id=ctx.account_id,
                                      region=GLOBAL_REGION, service="organizations", result_key="Accounts"):
            rec = new_record(ctx, service="organizations", resource_type="organizations:account",
                             resource_id=acct["Id"], arn=acct.get("Arn", ""), region=GLOBAL_REGION,
                             name=acct.get("Name", ""))
            rec.state_status = acct.get("Status", "")
            rec.creation_date = to_iso(acct.get("JoinedTimestamp"))
            rec.description_purpose = f"Org member account ({acct.get('Email','')})"
            rec.public_exposed = False
            rec.source_calls = ["organizations:ListAccounts"]
            out.append(rec)

        # SCPs (paginated) with policy body + attachment targets (R3).
        scps = ctx.call.paginate(client, "list_policies", account_id=ctx.account_id,
                                 region=GLOBAL_REGION, service="organizations",
                                 result_key="Policies", Filter="SERVICE_CONTROL_POLICY")
        for p in scps:
            pid = p.get("Id", "")
            rec = new_record(ctx, service="organizations", resource_type="organizations:scp",
                             resource_id=pid, arn=p.get("Arn", ""), region=GLOBAL_REGION,
                             name=p.get("Name", ""))
            rec.description_purpose = p.get("Description", "") or "Service Control Policy"
            rec.iam_policy_data["principal_type"] = "scp"
            # Policy body (Req 1/7 guardrail content) + attachment targets.
            body = ctx.call.call(client.describe_policy, account_id=ctx.account_id, region=GLOBAL_REGION,
                                 service="organizations", operation="DescribePolicy", resource_id=pid,
                                 default=None, PolicyId=pid)
            if body and body.get("Policy", {}).get("Content"):
                rec.iam_policy_data["document"] = body["Policy"]["Content"]
            targets = ctx.call.paginate(client, "list_targets_for_policy", account_id=ctx.account_id,
                                        region=GLOBAL_REGION, service="organizations",
                                        result_key="Targets", PolicyId=pid)
            tgt_ids = [t.get("TargetId") for t in targets]
            rec.add_relationship("attached_targets", tgt_ids)
            rec.state_status = f"targets={len(tgt_ids)}"
            rec.public_exposed = False
            rec.source_calls = ["organizations:ListPolicies", "organizations:DescribePolicy",
                                "organizations:ListTargetsForPolicy"]
            out.append(rec)

        # OU tree (R3): roots + OUs for scope-boundary visibility.
        roots = ctx.call.call(client.list_roots, account_id=ctx.account_id, region=GLOBAL_REGION,
                              service="organizations", operation="ListRoots", default={"Roots": []})
        for root in (roots or {}).get("Roots", []):
            out.extend(self._collect_ous(ctx, client, root.get("Id", ""), parent_name="root"))

        return out

    def _collect_ous(self, ctx: CollectorContext, client: Any, parent_id: str,
                     parent_name: str) -> list[ResourceRecord]:
        """Recursively enumerate OUs under a parent (organizations OU tree)."""
        out: list[ResourceRecord] = []
        ous = ctx.call.paginate(client, "list_organizational_units_for_parent",
                                account_id=ctx.account_id, region=GLOBAL_REGION,
                                service="organizations", result_key="OrganizationalUnits",
                                ParentId=parent_id)
        for ou in ous:
            oid = ou.get("Id", "")
            rec = new_record(ctx, service="organizations", resource_type="organizations:ou",
                             resource_id=oid, arn=ou.get("Arn", ""), region=GLOBAL_REGION,
                             name=ou.get("Name", ""))
            rec.description_purpose = f"Organizational Unit (parent: {parent_name})"
            rec.add_relationship("parent", parent_id)
            rec.public_exposed = False
            rec.source_calls = ["organizations:ListOrganizationalUnitsForParent"]
            out.append(rec)
            # Recurse one level of children.
            out.extend(self._collect_ous(ctx, client, oid, parent_name=ou.get("Name", oid)))
        return out


@register
class ControlTowerCollector(Collector):
    service = "controltower"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("controltower")
        resp = ctx.call.call(client.list_landing_zones, account_id=ctx.account_id, region=ctx.region,
                             service="controltower", operation="ListLandingZones", default=None)
        out: list[ResourceRecord] = []
        for lz in (resp or {}).get("landingZones", []):
            arn = lz.get("arn", "")
            rec = new_record(ctx, service="controltower", resource_type="controltower:landing-zone",
                             resource_id=arn.split("/")[-1] if arn else "landing-zone", arn=arn)
            rec.description_purpose = "Control Tower landing zone"
            rec.public_exposed = False
            rec.source_calls = ["controltower:ListLandingZones"]
            out.append(rec)
        return out
