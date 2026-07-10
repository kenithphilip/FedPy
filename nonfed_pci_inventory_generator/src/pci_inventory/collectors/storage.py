"""Storage collectors: S3 (with public-access/encryption/policy), EFS, FSx,
Storage Gateway, AWS Backup.

S3 is special: the bucket namespace is global (listed once), but per-bucket
attributes are fetched against each bucket's home region. The S3 collector is
therefore marked global and resolves bucket regions itself.
"""

from __future__ import annotations

from typing import Any

from pci_inventory.collectors.base import (
    Collector,
    CollectorContext,
    add_exposure,
    collect_each,
    new_record,
    register,
    set_not_exposed_if_unset,
    synth_arn,
    to_iso,
)
from pci_inventory.schema.models import ResourceRecord
from pci_inventory.utils import GLOBAL_REGION, Sentinel, tags_to_dict


@register
class S3Collector(Collector):
    """S3 buckets — global namespace, per-bucket attributes from the home region."""

    service = "s3"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("s3", region="us-east-1")
        resp = ctx.call.call(client.list_buckets, account_id=ctx.account_id, region=GLOBAL_REGION,
                             service="s3", operation="ListBuckets", default={"Buckets": []})
        # R3: account-level Block Public Access overrides per-bucket settings.
        account_pab_blocked = self._account_pab_blocked(ctx)
        records: list[ResourceRecord] = []
        for b in resp.get("Buckets", []):
            try:
                records.append(self._build(ctx, client, b, account_pab_blocked))
            except Exception:  # noqa: BLE001
                continue
        # Emit a synthetic account-settings record so the account PAB posture is visible.
        records.append(self._account_record(ctx, account_pab_blocked))
        return records

    def _account_pab_blocked(self, ctx: CollectorContext) -> bool | None:
        """Return True/False if account S3 Block Public Access is fully on, else None."""
        s3control = ctx.session.client("s3control", region="us-east-1")
        pab = ctx.call.call(s3control.get_public_access_block, account_id=ctx.account_id,
                            region=GLOBAL_REGION, service="s3", operation="GetPublicAccessBlock",
                            resource_id="account", default=None, AccountId=ctx.account_id)
        if pab is None:
            return None
        cfg = pab.get("PublicAccessBlockConfiguration", {})
        return all([cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                    cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")])

    def _account_record(self, ctx: CollectorContext, blocked: bool | None) -> ResourceRecord:
        rec = new_record(ctx, service="s3", resource_type="s3:account-public-access",
                         resource_id=ctx.account_id, region=GLOBAL_REGION,
                         arn=f"arn:aws:s3:::account/{ctx.account_id}", name="s3-account-public-access")
        rec.description_purpose = "Account-level S3 Block Public Access posture"
        rec.public_access_block = blocked
        rec.state_status = "fully-blocked" if blocked else ("not-fully-blocked" if blocked is False else Sentinel.UNKNOWN)
        rec.public_exposed = False
        rec.source_calls = ["s3control:GetPublicAccessBlock"]
        return rec

    def _bucket_region(self, ctx: CollectorContext, client: Any, name: str) -> str:
        loc = ctx.call.call(client.get_bucket_location, account_id=ctx.account_id, region=GLOBAL_REGION,
                            service="s3", operation="GetBucketLocation", resource_id=name,
                            default={}, Bucket=name)
        constraint = (loc or {}).get("LocationConstraint")
        return constraint or "us-east-1"  # null == us-east-1

    def _build(self, ctx: CollectorContext, client: Any, b: dict[str, Any],
               account_pab_blocked: bool | None) -> ResourceRecord:
        name = b["Name"]
        region = self._bucket_region(ctx, client, name)
        # Use a region-correct client for the remaining bucket sub-resource calls.
        rclient = ctx.session.client("s3", region=region)
        arn = f"arn:aws:s3:::{name}"
        rec = new_record(ctx, service="s3", resource_type="s3:bucket",
                         resource_id=name, arn=arn, region=region, name=name)
        rec.creation_date = to_iso(b.get("CreationDate"))
        rec.description_purpose = "S3 bucket (object storage)"
        rec.dns_names = [f"{name}.s3.{region}.amazonaws.com"]
        rec.source_calls = ["s3:ListBuckets", "s3:GetBucketLocation"]

        # Tags.
        tagging = ctx.call.call(rclient.get_bucket_tagging, account_id=ctx.account_id, region=region,
                                service="s3", operation="GetBucketTagging", resource_id=name,
                                default={"TagSet": []}, Bucket=name)
        rec.tags = tags_to_dict((tagging or {}).get("TagSet"))

        # Encryption at rest. Track whether the call errored so an AccessDenied is
        # not silently reported as "encrypted by default".
        _err_before = len(ctx.call.errors.errors)
        enc = ctx.call.call(rclient.get_bucket_encryption, account_id=ctx.account_id, region=region,
                            service="s3", operation="GetBucketEncryption", resource_id=name,
                            default=None, Bucket=name)
        enc_errored = len(ctx.call.errors.errors) > _err_before
        if enc:
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            algos = [r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                     for r in rules]
            rec.encryption_at_rest = True
            rec.encryption_at_rest_detail = ", ".join(a for a in algos if a)
            for r in rules:
                kms = r.get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID")
                if kms:
                    rec.add_relationship("kms_key", kms)
        elif enc_errored:
            # M4 fix: do NOT assert an unverified control when the call was denied.
            rec.encryption_at_rest = None
            rec.encryption_at_rest_detail = Sentinel.ACCESS_DENIED
            rec.add_note("encryption config not readable (ACCESS_DENIED)")
        else:
            # No explicit config returned, but S3 enforces SSE-S3 by default
            # since Jan 2023 — report True with the AWS-default basis.
            rec.encryption_at_rest = True
            rec.encryption_at_rest_detail = "SSE-S3 (AWS default; no explicit bucket config)"
        rec.source_calls.append("s3:GetBucketEncryption")

        # Versioning + logging.
        ver = ctx.call.call(rclient.get_bucket_versioning, account_id=ctx.account_id, region=region,
                            service="s3", operation="GetBucketVersioning", resource_id=name,
                            default={}, Bucket=name)
        rec.backup_config = f"versioning={ (ver or {}).get('Status','Disabled') }"
        log_cfg = ctx.call.call(rclient.get_bucket_logging, account_id=ctx.account_id, region=region,
                                service="s3", operation="GetBucketLogging", resource_id=name,
                                default={}, Bucket=name)
        if (log_cfg or {}).get("LoggingEnabled"):
            rec.logging_enabled = True
            rec.logging_detail = f"access logs → {log_cfg['LoggingEnabled'].get('TargetBucket','')}"
        else:
            rec.logging_enabled = False

        # R3: object lock (WORM/immutability — log & data retention integrity).
        lock = ctx.call.call(rclient.get_object_lock_configuration, account_id=ctx.account_id, region=region,
                             service="s3", operation="GetObjectLockConfiguration", resource_id=name,
                             default=None, Bucket=name)
        if lock and lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled":
            rec.add_note("object-lock enabled (WORM)")
            rec.backup_config += "; object-lock=Enabled"
        # R3: MFA delete (from versioning response).
        if (ver or {}).get("MFADelete") == "Enabled":
            rec.backup_config += "; mfa-delete=Enabled"

        # Public access: Public Access Block + policy status + ACL (account-PAB aware).
        self._assess_public(ctx, rclient, name, region, rec, account_pab_blocked)
        set_not_exposed_if_unset(rec)
        return rec

    def _assess_public(self, ctx: CollectorContext, rclient: Any, name: str, region: str,
                       rec: ResourceRecord, account_pab_blocked: bool | None) -> None:
        """Assess bucket public access from PAB + policy status, account PAB-aware.

        Distinguishes AccessDenied (status undetermined → never asserts not-public)
        from a genuinely-absent policy/PAB. Sets the typed ``public_access_block``
        column. An account-level Block Public Access (passed in) overrides per
        bucket — if the account fully blocks, the bucket cannot be public.
        """
        _err0 = len(ctx.call.errors.errors)
        pab = ctx.call.call(rclient.get_public_access_block, account_id=ctx.account_id, region=region,
                            service="s3", operation="GetPublicAccessBlock", resource_id=name,
                            default=None, Bucket=name)
        pab_errored = len(ctx.call.errors.errors) > _err0
        pab_cfg = (pab or {}).get("PublicAccessBlockConfiguration", {})
        bucket_fully_blocked = all([
            pab_cfg.get("BlockPublicAcls"), pab_cfg.get("IgnorePublicAcls"),
            pab_cfg.get("BlockPublicPolicy"), pab_cfg.get("RestrictPublicBuckets"),
        ]) if pab_cfg else False
        rec.iam_policy_data["public_access_block"] = pab_cfg or "not-configured"

        fully_blocked = bucket_fully_blocked or bool(account_pab_blocked)
        # Typed column: Yes only when effective PAB fully blocks; No when readable
        # and not fully blocking; None (N/A) when the deciding call was denied.
        if pab_errored and not pab_cfg and account_pab_blocked is None:
            rec.public_access_block = None
            rec.add_note("Public Access Block not readable (ACCESS_DENIED)")
        else:
            rec.public_access_block = fully_blocked

        _err1 = len(ctx.call.errors.errors)
        status = ctx.call.call(rclient.get_bucket_policy_status, account_id=ctx.account_id, region=region,
                               service="s3", operation="GetBucketPolicyStatus", resource_id=name,
                               default=None, Bucket=name)
        status_errored = len(ctx.call.errors.errors) > _err1
        policy_public = bool((status or {}).get("PolicyStatus", {}).get("IsPublic"))

        policy = ctx.call.call(rclient.get_bucket_policy, account_id=ctx.account_id, region=region,
                               service="s3", operation="GetBucketPolicy", resource_id=name,
                               default=None, Bucket=name)
        if policy and policy.get("Policy"):
            rec.iam_policy_data["resource_based_policy"] = policy["Policy"]

        if policy_public and not fully_blocked:
            add_exposure(rec, "s3-bucket-policy-public")
        elif status_errored and not fully_blocked:
            # Could not compute public status and PAB does not save us — mark unknown.
            rec.public_exposed = None
            rec.add_note("public status undetermined (GetBucketPolicyStatus ACCESS_DENIED)")
        if not fully_blocked and not pab_cfg and not pab_errored:
            rec.add_note("no Public Access Block configured")
        rec.source_calls += ["s3:GetPublicAccessBlock", "s3:GetBucketPolicyStatus", "s3:GetBucketPolicy"]


@register
class EFSCollector(Collector):
    service = "efs"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("efs")
        fs = ctx.call.paginate(client, "describe_file_systems", account_id=ctx.account_id,
                               region=ctx.region, service="efs", result_key="FileSystems")
        return collect_each(fs, lambda f: self._build(ctx, f))

    def _build(self, ctx: CollectorContext, fs: dict[str, Any]) -> ResourceRecord:
        fid = fs["FileSystemId"]
        arn = fs.get("FileSystemArn", "") or synth_arn("elasticfilesystem", ctx.region, ctx.account_id, f"file-system/{fid}")
        rec = new_record(ctx, service="efs", resource_type="efs:file-system",
                         resource_id=fid, arn=arn, name=fs.get("Name", ""))
        rec.tags = tags_to_dict(fs.get("Tags"))
        rec.state_status = fs.get("LifeCycleState", "")
        rec.creation_date = to_iso(fs.get("CreationTime"))
        rec.encryption_at_rest = bool(fs.get("Encrypted", False))
        if fs.get("KmsKeyId"):
            rec.encryption_at_rest_detail = f"kms {fs['KmsKeyId']}"
            rec.add_relationship("kms_key", fs["KmsKeyId"])
        rec.description_purpose = "EFS file system"
        rec.public_exposed = False
        rec.source_calls = ["efs:DescribeFileSystems"]
        return rec


@register
class FSxCollector(Collector):
    service = "fsx"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("fsx")
        fs = ctx.call.paginate(client, "describe_file_systems", account_id=ctx.account_id,
                               region=ctx.region, service="fsx", result_key="FileSystems")
        return collect_each(fs, lambda f: self._build(ctx, f))

    def _build(self, ctx: CollectorContext, fs: dict[str, Any]) -> ResourceRecord:
        fid = fs["FileSystemId"]
        rec = new_record(ctx, service="fsx", resource_type="fsx:file-system",
                         resource_id=fid, arn=fs.get("ResourceARN", ""))
        rec.tags = tags_to_dict(fs.get("Tags"))
        rec.state_status = fs.get("Lifecycle", "")
        rec.creation_date = to_iso(fs.get("CreationTime"))
        rec.os_platform_engine = fs.get("FileSystemType", "")
        rec.encryption_at_rest = bool(fs.get("KmsKeyId"))
        if fs.get("KmsKeyId"):
            rec.add_relationship("kms_key", fs["KmsKeyId"])
        rec.add_relationship("vpc", fs.get("VpcId"))
        rec.add_relationship("subnets", fs.get("SubnetIds", []))
        rec.description_purpose = f"FSx {fs.get('FileSystemType','')} file system"
        rec.public_exposed = False
        rec.source_calls = ["fsx:DescribeFileSystems"]
        return rec


@register
class StorageGatewayCollector(Collector):
    service = "storagegateway"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("storagegateway")
        gws = ctx.call.paginate(client, "list_gateways", account_id=ctx.account_id,
                                region=ctx.region, service="storagegateway", result_key="Gateways")
        return collect_each(gws, lambda g: self._build(ctx, g))

    def _build(self, ctx: CollectorContext, gw: dict[str, Any]) -> ResourceRecord:
        rec = new_record(ctx, service="storagegateway", resource_type="storagegateway:gateway",
                         resource_id=gw.get("GatewayId", ""), arn=gw.get("GatewayARN", ""),
                         name=gw.get("GatewayName", ""))
        rec.state_status = gw.get("GatewayOperationalState", "")
        rec.os_platform_engine = gw.get("GatewayType", "")
        rec.description_purpose = "Storage Gateway"
        rec.public_exposed = False
        rec.source_calls = ["storagegateway:ListGateways"]
        return rec


@register
class BackupCollector(Collector):
    service = "backup"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("backup")
        vaults = ctx.call.paginate(client, "list_backup_vaults", account_id=ctx.account_id,
                                   region=ctx.region, service="backup", result_key="BackupVaultList")
        return collect_each(vaults, lambda v: self._build(ctx, v))

    def _build(self, ctx: CollectorContext, v: dict[str, Any]) -> ResourceRecord:
        name = v["BackupVaultName"]
        rec = new_record(ctx, service="backup", resource_type="backup:vault",
                         resource_id=name, arn=v.get("BackupVaultArn", ""), name=name)
        rec.creation_date = to_iso(v.get("CreationDate"))
        rec.encryption_at_rest = bool(v.get("EncryptionKeyArn"))
        if v.get("EncryptionKeyArn"):
            rec.add_relationship("kms_key", v["EncryptionKeyArn"])
        rec.backup_config = f"recovery_points={v.get('NumberOfRecoveryPoints',0)}"
        rec.description_purpose = "AWS Backup vault"
        rec.public_exposed = False
        rec.source_calls = ["backup:ListBackupVaults"]
        return rec
