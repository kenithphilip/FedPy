"""IAM & access collectors (GLOBAL): users, groups, roles, managed+inline
policies, instance profiles, access keys + age, MFA, password policy, account
summary, SAML/OIDC providers, plus regional Cognito and Access Analyzer.

Throttle-efficient design (re-audit):
- **One paginated ``GetAccountAuthorizationDetails``** returns all users, groups,
  roles, their attached managed-policy ARNs, inline policy docs, and (for roles)
  trust policies — replacing dozens of per-principal ``List*``/``Get*`` calls.
- The **credential report** (one call) supplies per-user MFA, password, access-key
  age, and last-used data; ``GetCredentialReport`` is tried first and only
  generated if absent.
- Customer-managed policies are emitted in full; AWS-managed policies only where
  attached to a principal (bounded, relevant).

New typed columns populated here: ``mfa_enabled``, ``mfa_type``,
``access_key_age_days``, ``last_used_age_days``, ``is_root_account``,
``password_policy_summary``. Never captures secret material.
"""

from __future__ import annotations

import csv
import io
import json
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from pci_inventory.collectors.base import (
    Collector,
    CollectorContext,
    new_record,
    register,
    to_iso,
)
from pci_inventory.schema.models import ResourceRecord
from pci_inventory.utils import GLOBAL_REGION, Sentinel, utc_now


def _global_record(ctx: CollectorContext, **kw: Any) -> ResourceRecord:
    kw.setdefault("region", GLOBAL_REGION)
    return new_record(ctx, **kw)


def _age_days(value: str | None) -> str:
    """Days since an ISO/credential-report timestamp, as a string, else N/A."""
    if not value or value in ("N/A", "no_information", "not_supported", ""):
        return Sentinel.NA
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return str((utc_now() - dt).days)
    except (ValueError, TypeError):
        return Sentinel.NA


def _min_age_days(*values: str) -> str:
    """Smallest non-N/A age among the given age strings (most recent activity)."""
    nums = [int(v) for v in values if v not in (Sentinel.NA, "")]
    return str(min(nums)) if nums else Sentinel.NA


def _max_age_days(*values: str) -> str:
    """Largest non-N/A age (oldest key) among the given age strings."""
    nums = [int(v) for v in values if v not in (Sentinel.NA, "")]
    return str(max(nums)) if nums else Sentinel.NA


@register
class IAMCollector(Collector):
    """All core IAM principals + policies + account-level settings (global)."""

    service = "iam"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        iam = ctx.client("iam", region=None)
        records: list[ResourceRecord] = []
        cred = self._get_credential_report(ctx, iam)

        # One bulk pull of principals + policies + inline docs + trust policies.
        details = self._get_authorization_details(ctx, iam)
        attached_aws: set[str] = set()

        records += self._build_users(ctx, details.get("UserDetailList", []), cred, attached_aws)
        records += self._build_groups(ctx, details.get("GroupDetailList", []), attached_aws)
        records += self._build_roles(ctx, details.get("RoleDetailList", []), attached_aws)
        records += self._build_policies(ctx, iam, details.get("Policies", []), attached_aws)
        records += self._collect_instance_profiles(ctx, iam)
        records += self._collect_account_settings(ctx, iam, cred)
        records += self._collect_providers(ctx, iam)
        records += self._collect_server_certificates(ctx, iam)
        return records

    # -- bulk authorization details --------------------------------------- #
    def _get_authorization_details(self, ctx: CollectorContext, iam: Any) -> dict[str, list]:
        """Aggregate all pages of GetAccountAuthorizationDetails into one dict."""
        agg: dict[str, list] = {
            "UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": [],
        }
        pages = ctx.call.paginate(
            iam, "get_account_authorization_details", account_id=ctx.account_id,
            region=GLOBAL_REGION, service="iam", result_key=None,
            Filter=["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"],
        )
        for page in pages:
            for key in agg:
                agg[key].extend(page.get(key, []))
        return agg

    # -- credential report ------------------------------------------------- #
    def _get_credential_report(self, ctx: CollectorContext, iam: Any) -> dict[str, dict[str, str]]:
        """Fetch the IAM credential report (generate only if not already present)."""
        report = ctx.call.call(iam.get_credential_report, account_id=ctx.account_id,
                               region=GLOBAL_REGION, service="iam",
                               operation="GetCredentialReport", default=None)
        if not report:
            # Not present yet — generate once, then re-fetch.
            ctx.call.call(iam.generate_credential_report, account_id=ctx.account_id,
                          region=GLOBAL_REGION, service="iam",
                          operation="GenerateCredentialReport", default=None)
            report = ctx.call.call(iam.get_credential_report, account_id=ctx.account_id,
                                   region=GLOBAL_REGION, service="iam",
                                   operation="GetCredentialReport", default=None)
        out: dict[str, dict[str, str]] = {}
        if report and report.get("Content"):
            content = report["Content"]
            text = content.decode("utf-8") if isinstance(content, bytes) else content
            for row in csv.DictReader(io.StringIO(text)):
                out[row.get("arn", "")] = row
        return out

    # -- users ------------------------------------------------------------- #
    def _build_users(self, ctx: CollectorContext, users: list[dict[str, Any]],
                     cred: dict[str, dict[str, str]], attached_aws: set[str]) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        for user in users:
            name = user["UserName"]
            arn = user["Arn"]
            rec = _global_record(ctx, service="iam", resource_type="iam:user",
                                  resource_id=name, arn=arn, name=name)
            rec.creation_date = to_iso(user.get("CreateDate"))
            rec.description_purpose = "IAM user"
            row = cred.get(arn, {})

            policy_data: dict[str, Any] = {"principal_type": "user"}
            attached = [p.get("PolicyArn") for p in user.get("AttachedManagedPolicies", [])]
            policy_data["attached_managed_policies"] = attached
            rec.add_relationship("attached_policies", attached)
            for a in attached:
                if a and ":aws:policy/" in a:
                    attached_aws.add(a)
            policy_data["inline_policies"] = {
                p.get("PolicyName"): _maybe_decode_policy(p.get("PolicyDocument"))
                for p in user.get("UserPolicyList", [])
            }
            rec.add_relationship("groups", user.get("GroupList", []))
            if user.get("PermissionsBoundary"):
                policy_data["permissions_boundary"] = user["PermissionsBoundary"].get("PermissionsBoundaryArn")

            # Typed identity columns from the credential report.
            mfa = row.get("mfa_active") == "true"
            rec.mfa_enabled = mfa if row else None
            k1_age = _age_days(row.get("access_key_1_last_rotated"))
            k2_age = _age_days(row.get("access_key_2_last_rotated"))
            rec.access_key_age_days = _max_age_days(k1_age, k2_age)
            pw_used = _age_days(row.get("password_last_used"))
            k1_used = _age_days(row.get("access_key_1_last_used_date"))
            k2_used = _age_days(row.get("access_key_2_last_used_date"))
            rec.last_used_age_days = _min_age_days(pw_used, k1_used, k2_used)
            rec.last_modified_activity = to_iso(user.get("CreateDate"))
            rec.is_root_account = False
            console = row.get("password_enabled") == "true"
            rec.state_status = (f"mfa={'yes' if mfa else 'no'} console={'yes' if console else 'no'} "
                                f"keys={'+'.join(k for k, on in [('1', row.get('access_key_1_active')=='true'), ('2', row.get('access_key_2_active')=='true')] if on) or 'none'}")
            policy_data["password_enabled"] = row.get("password_enabled")
            policy_data["mfa_active"] = row.get("mfa_active")
            policy_data["access_keys"] = [
                {"slot": "1", "active": row.get("access_key_1_active"),
                 "last_rotated": row.get("access_key_1_last_rotated"),
                 "last_used": row.get("access_key_1_last_used_date")},
                {"slot": "2", "active": row.get("access_key_2_active"),
                 "last_rotated": row.get("access_key_2_last_rotated"),
                 "last_used": row.get("access_key_2_last_used_date")},
            ]
            if mfa is False and console:
                rec.add_note("console user without MFA (review 8.4)")
            if rec.access_key_age_days not in (Sentinel.NA, "") and int(rec.access_key_age_days) > 90:
                rec.add_note(f"access key age {rec.access_key_age_days}d > 90 (review 8.3.9)")

            rec.iam_policy_data = policy_data
            rec.public_exposed = False
            rec.source_calls = ["iam:GetAccountAuthorizationDetails", "iam:GetCredentialReport"]
            out.append(rec)
        return out

    # -- groups ------------------------------------------------------------ #
    def _build_groups(self, ctx: CollectorContext, groups: list[dict[str, Any]],
                      attached_aws: set[str]) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        for group in groups:
            name = group["GroupName"]
            rec = _global_record(ctx, service="iam", resource_type="iam:group",
                                  resource_id=name, arn=group["Arn"], name=name)
            rec.creation_date = to_iso(group.get("CreateDate"))
            rec.description_purpose = "IAM group"
            policy_data: dict[str, Any] = {"principal_type": "group"}
            attached = [p.get("PolicyArn") for p in group.get("AttachedManagedPolicies", [])]
            policy_data["attached_managed_policies"] = attached
            rec.add_relationship("attached_policies", attached)
            for a in attached:
                if a and ":aws:policy/" in a:
                    attached_aws.add(a)
            policy_data["inline_policies"] = {
                p.get("PolicyName"): _maybe_decode_policy(p.get("PolicyDocument"))
                for p in group.get("GroupPolicyList", [])
            }
            rec.iam_policy_data = policy_data
            rec.public_exposed = False
            rec.source_calls = ["iam:GetAccountAuthorizationDetails"]
            out.append(rec)
        return out

    # -- roles ------------------------------------------------------------- #
    def _build_roles(self, ctx: CollectorContext, roles: list[dict[str, Any]],
                     attached_aws: set[str]) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        for role in roles:
            name = role["RoleName"]
            rec = _global_record(ctx, service="iam", resource_type="iam:role",
                                  resource_id=name, arn=role["Arn"], name=name)
            rec.creation_date = to_iso(role.get("CreateDate"))
            rec.description_purpose = role.get("Description", "") or "IAM role"
            last_used = role.get("RoleLastUsed", {}).get("LastUsedDate")
            rec.last_used_age_days = _age_days(to_iso(last_used)) if last_used else Sentinel.NA
            rec.last_modified_activity = to_iso(last_used)
            policy_data: dict[str, Any] = {"principal_type": "role"}
            trust = _maybe_decode_policy(role.get("AssumeRolePolicyDocument"))
            policy_data["trust_policy"] = trust
            trust_principals = self._extract_trust_principals(trust)
            policy_data["trust_principals"] = trust_principals
            rec.add_relationship("trust_principals", trust_principals)
            attached = [p.get("PolicyArn") for p in role.get("AttachedManagedPolicies", [])]
            policy_data["attached_managed_policies"] = attached
            rec.add_relationship("attached_policies", attached)
            for a in attached:
                if a and ":aws:policy/" in a:
                    attached_aws.add(a)
            policy_data["inline_policies"] = {
                p.get("PolicyName"): _maybe_decode_policy(p.get("PolicyDocument"))
                for p in role.get("RolePolicyList", [])
            }
            if role.get("PermissionsBoundary"):
                policy_data["permissions_boundary"] = role["PermissionsBoundary"].get("PermissionsBoundaryArn")
            if any(p == "*" or ":root" in str(p) for p in trust_principals):
                rec.add_note("trust policy allows external/root principal (review 7.x)")
            rec.iam_policy_data = policy_data
            rec.public_exposed = False
            rec.source_calls = ["iam:GetAccountAuthorizationDetails"]
            out.append(rec)
        return out

    def _extract_trust_principals(self, trust: Any) -> list[str]:
        principals: list[str] = []
        if not isinstance(trust, dict):
            return principals
        for stmt in trust.get("Statement", []):
            pr = stmt.get("Principal", {})
            if pr == "*":
                principals.append("*")
            elif isinstance(pr, dict):
                for v in pr.values():
                    principals.extend(v if isinstance(v, list) else [v])
        return principals

    # -- managed policies -------------------------------------------------- #
    def _build_policies(self, ctx: CollectorContext, iam: Any, policies: list[dict[str, Any]],
                        attached_aws: set[str]) -> list[ResourceRecord]:
        """Customer-managed policies in full; AWS-managed only where attached."""
        out: list[ResourceRecord] = []
        for pol in policies:
            arn = pol.get("Arn", "")
            is_aws = ":aws:policy/" in arn
            if is_aws and arn not in attached_aws:
                continue  # AWS-managed but unattached — skip (bounded inventory).
            name = pol.get("PolicyName", "")
            managed_by = "aws" if is_aws else "customer"
            rec = _global_record(ctx, service="iam", resource_type=f"iam:policy-{managed_by}",
                                  resource_id=name, arn=arn, name=name)
            rec.creation_date = to_iso(pol.get("CreateDate"))
            rec.last_modified_activity = to_iso(pol.get("UpdateDate"))
            rec.description_purpose = pol.get("Description", "") or f"{managed_by}-managed IAM policy"
            rec.state_status = f"attachments={pol.get('AttachmentCount', 0)}"
            policy_data: dict[str, Any] = {"principal_type": "policy", "managed_by": managed_by}
            # Default version document is embedded in PolicyVersionList.
            default_ver = pol.get("DefaultVersionId")
            for ver in pol.get("PolicyVersionList", []):
                if ver.get("VersionId") == default_ver or ver.get("IsDefaultVersion"):
                    policy_data["document"] = _maybe_decode_policy(ver.get("Document"))
                    break
            rec.iam_policy_data = policy_data
            rec.public_exposed = False
            rec.source_calls = ["iam:GetAccountAuthorizationDetails"]
            out.append(rec)
        return out

    # -- instance profiles ------------------------------------------------- #
    def _collect_instance_profiles(self, ctx: CollectorContext, iam: Any) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        for prof in ctx.call.paginate(iam, "list_instance_profiles", account_id=ctx.account_id,
                                      region=GLOBAL_REGION, service="iam", result_key="InstanceProfiles"):
            name = prof["InstanceProfileName"]
            rec = _global_record(ctx, service="iam", resource_type="iam:instance-profile",
                                  resource_id=name, arn=prof["Arn"], name=name)
            rec.creation_date = to_iso(prof.get("CreateDate"))
            rec.description_purpose = "IAM instance profile"
            rec.add_relationship("roles", [r.get("RoleName") for r in prof.get("Roles", [])])
            rec.iam_policy_data = {"principal_type": "instance-profile",
                                   "roles": [r.get("Arn") for r in prof.get("Roles", [])]}
            rec.public_exposed = False
            rec.source_calls = ["iam:ListInstanceProfiles"]
            out.append(rec)
        return out

    # -- account-level settings ------------------------------------------- #
    def _collect_account_settings(self, ctx: CollectorContext, iam: Any,
                                  cred: dict[str, dict[str, str]]) -> list[ResourceRecord]:
        rec = _global_record(ctx, service="iam", resource_type="iam:account-settings",
                             resource_id=ctx.account_id, arn=f"arn:aws:iam::{ctx.account_id}:account",
                             name="account-settings")
        rec.description_purpose = "Account-level IAM settings (password policy, root usage, summary)"
        rec.is_root_account = None  # this is the account-settings record, not a principal

        pw = ctx.call.call(iam.get_account_password_policy, account_id=ctx.account_id, region=GLOBAL_REGION,
                           service="iam", operation="GetAccountPasswordPolicy", default=None)
        summary = ctx.call.call(iam.get_account_summary, account_id=ctx.account_id, region=GLOBAL_REGION,
                                service="iam", operation="GetAccountSummary", default={})
        data: dict[str, Any] = {"principal_type": "account-settings"}
        if pw and pw.get("PasswordPolicy"):
            p = pw["PasswordPolicy"]
            data["password_policy"] = p
            rec.password_policy_summary = (
                f"len={p.get('MinimumPasswordLength','?')} reuse={p.get('PasswordReusePrevention','none')} "
                f"maxage={p.get('MaxPasswordAge','none')} "
                f"sym={int(bool(p.get('RequireSymbols')))} num={int(bool(p.get('RequireNumbers')))} "
                f"upper={int(bool(p.get('RequireUppercaseCharacters')))} lower={int(bool(p.get('RequireLowercaseCharacters')))}"
            )
            if p.get("MinimumPasswordLength", 0) < 12:
                rec.add_note("password min length < 12 (review 8.3.6)")
        else:
            data["password_policy"] = "NOT_SET"
            rec.password_policy_summary = "NOT_SET (AWS defaults)"
            rec.add_note("no account password policy set (review 8.3.x)")
        data["account_summary"] = (summary or {}).get("SummaryMap", {})

        # Root usage indicators from credential report.
        root = cred.get(f"arn:aws:iam::{ctx.account_id}:root", {})
        if root:
            rec.is_root_account = True
            rec.mfa_enabled = root.get("mfa_active") == "true"
            data["root_mfa_active"] = root.get("mfa_active")
            data["root_password_last_used"] = root.get("password_last_used")
            data["root_access_key_1_active"] = root.get("access_key_1_active")
            data["root_access_key_2_active"] = root.get("access_key_2_active")
            rec.last_used_age_days = _age_days(root.get("password_last_used"))
            if root.get("access_key_1_active") == "true" or root.get("access_key_2_active") == "true":
                rec.add_note("ROOT ACCESS KEY ACTIVE — review (8.2.2/8.6.1)")
            if root.get("mfa_active") == "false":
                rec.add_note("ROOT MFA NOT ACTIVE — review (8.4.x)")
        rec.iam_policy_data = data
        rec.state_status = "password-policy=" + ("set" if data["password_policy"] != "NOT_SET" else "default")
        rec.public_exposed = False
        rec.source_calls = ["iam:GetAccountPasswordPolicy", "iam:GetAccountSummary", "iam:GetCredentialReport"]
        return [rec]

    # -- identity providers ----------------------------------------------- #
    def _collect_providers(self, ctx: CollectorContext, iam: Any) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        saml = ctx.call.call(iam.list_saml_providers, account_id=ctx.account_id, region=GLOBAL_REGION,
                             service="iam", operation="ListSAMLProviders", default={"SAMLProviderList": []})
        for p in (saml or {}).get("SAMLProviderList", []):
            arn = p["Arn"]
            rec = _global_record(ctx, service="iam", resource_type="iam:saml-provider",
                                 resource_id=arn.split("/")[-1], arn=arn, name=arn.split("/")[-1])
            rec.creation_date = to_iso(p.get("CreateDate"))
            rec.description_purpose = "SAML identity provider (federation)"
            rec.public_exposed = False
            rec.source_calls = ["iam:ListSAMLProviders"]
            out.append(rec)
        oidc = ctx.call.call(iam.list_open_id_connect_providers, account_id=ctx.account_id, region=GLOBAL_REGION,
                             service="iam", operation="ListOpenIDConnectProviders",
                             default={"OpenIDConnectProviderList": []})
        for p in (oidc or {}).get("OpenIDConnectProviderList", []):
            arn = p["Arn"]
            rec = _global_record(ctx, service="iam", resource_type="iam:oidc-provider",
                                 resource_id=arn.split("/")[-1], arn=arn, name=arn.split("/")[-1])
            rec.description_purpose = "OIDC identity provider (federation)"
            rec.public_exposed = False
            rec.source_calls = ["iam:ListOpenIDConnectProviders"]
            out.append(rec)
        return out

    # -- server certificates (legacy / deprecated TLS certs) -------------- #
    def _collect_server_certificates(self, ctx: CollectorContext, iam: Any) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        for c in ctx.call.paginate(iam, "list_server_certificates", account_id=ctx.account_id,
                                   region=GLOBAL_REGION, service="iam",
                                   result_key="ServerCertificateMetadataList"):
            name = c.get("ServerCertificateName", "")
            rec = _global_record(ctx, service="iam", resource_type="iam:server-certificate",
                                 resource_id=name, arn=c.get("Arn", ""), name=name)
            rec.description_purpose = "IAM server certificate (legacy TLS cert store)"
            rec.cert_expiry_date = to_iso(c.get("Expiration"))
            rec.creation_date = to_iso(c.get("UploadDate"))
            rec.encryption_in_transit = True
            rec.add_note("IAM server certs are legacy — prefer ACM (review 4.2.1)")
            rec.public_exposed = False
            rec.source_calls = ["iam:ListServerCertificates"]
            out.append(rec)
        return out


def _maybe_decode_policy(doc: Any) -> Any:
    """Policy documents may be URL-encoded JSON strings; decode best-effort."""
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except Exception:  # noqa: BLE001
            return doc
    return doc


@register
class CognitoCollector(Collector):
    """Cognito user pools + identity pools (regional)."""

    service = "cognito-idp"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        idp = ctx.client("cognito-idp")
        pools = ctx.call.call(idp.list_user_pools, account_id=ctx.account_id, region=ctx.region,
                              service="cognito-idp", operation="ListUserPools",
                              default={"UserPools": []}, MaxResults=60)
        for p in pools.get("UserPools", []):
            pid = p["Id"]
            rec = new_record(ctx, service="cognito-idp", resource_type="cognito:user-pool",
                             resource_id=pid, arn=f"arn:aws:cognito-idp:{ctx.region}:{ctx.account_id}:userpool/{pid}",
                             name=p.get("Name", ""))
            rec.creation_date = to_iso(p.get("CreationDate"))
            rec.last_modified_activity = to_iso(p.get("LastModifiedDate"))
            rec.description_purpose = "Cognito user pool (identity store)"
            # R3: MFA config (Req 8.4/8.5).
            mfa = ctx.call.call(idp.get_user_pool_mfa_config, account_id=ctx.account_id, region=ctx.region,
                                service="cognito-idp", operation="GetUserPoolMfaConfig", resource_id=pid,
                                default=None, UserPoolId=pid)
            if mfa:
                mode = mfa.get("MfaConfiguration", "OFF")
                rec.mfa_enabled = mode != "OFF"
                rec.state_status = f"mfa={mode}"
                if mode == "OFF":
                    rec.add_note("user pool MFA OFF (review 8.4)")
            rec.public_exposed = False
            rec.source_calls = ["cognito-idp:ListUserPools", "cognito-idp:GetUserPoolMfaConfig"]
            out.append(rec)

        idc = ctx.client("cognito-identity")
        ipools = ctx.call.call(idc.list_identity_pools, account_id=ctx.account_id, region=ctx.region,
                               service="cognito-identity", operation="ListIdentityPools",
                               default={"IdentityPools": []}, MaxResults=60)
        for p in ipools.get("IdentityPools", []):
            rec = new_record(ctx, service="cognito-identity", resource_type="cognito:identity-pool",
                             resource_id=p["IdentityPoolId"],
                             arn=f"arn:aws:cognito-identity:{ctx.region}:{ctx.account_id}:identitypool/{p['IdentityPoolId']}",
                             name=p.get("IdentityPoolName", ""))
            rec.description_purpose = "Cognito identity pool (federated identities)"
            rec.public_exposed = False
            rec.source_calls = ["cognito-identity:ListIdentityPools"]
            out.append(rec)
        return out


@register
class AccessAnalyzerCollector(Collector):
    service = "access-analyzer"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("accessanalyzer")
        resp = ctx.call.call(client.list_analyzers, account_id=ctx.account_id, region=ctx.region,
                             service="access-analyzer", operation="ListAnalyzers", default={"analyzers": []})
        out = []
        for a in resp.get("analyzers", []):
            arn = a.get("arn", "")
            rec = new_record(ctx, service="access-analyzer", resource_type="access-analyzer:analyzer",
                             resource_id=a.get("name", ""), arn=arn, name=a.get("name", ""))
            rec.state_status = a.get("status", "")
            rec.creation_date = to_iso(a.get("createdAt"))
            rec.description_purpose = f"IAM Access Analyzer ({a.get('type','')})"
            # R3: count active external-access findings (Req 1.3/7.2).
            findings = ctx.call.paginate(client, "list_findings", account_id=ctx.account_id,
                                         region=ctx.region, service="access-analyzer",
                                         result_key="findings", analyzerArn=arn,
                                         filter={"status": {"eq": ["ACTIVE"]}})
            active = sum(1 for f in findings if f.get("status") == "ACTIVE")
            rec.vuln_findings_summary = f"active-external-access-findings={active}"
            if active:
                rec.add_note(f"{active} active external-access findings (review 1.3/7.2)")
            rec.public_exposed = False
            rec.source_calls = ["accessanalyzer:ListAnalyzers", "accessanalyzer:ListFindings"]
            out.append(rec)
        return out
