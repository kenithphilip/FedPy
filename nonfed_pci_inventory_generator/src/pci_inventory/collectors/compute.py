"""Compute collectors: EC2 instances, AMIs, EBS volumes/snapshots, ASGs, launch
templates/configs, Lambda, ECS, EKS, ECR, Batch, Lightsail, Elastic Beanstalk.

All calls are read-only Describe/List/Get. Records capture exposure signals
(public IPs), encryption-at-rest, platform/engine, bespoke-software flags, and the
relationship references Stage 2 needs (ENIs, volumes, security groups, roles).
"""

from __future__ import annotations

from typing import Any

from pci_inventory.collectors.base import (
    Collector,
    CollectorContext,
    add_exposure,
    assess_resource_policy_exposure,
    collect_each,
    new_record,
    register,
    set_not_exposed_if_unset,
    synth_arn,
    to_iso,
)
from pci_inventory.schema.models import ResourceRecord
from pci_inventory.utils import Sentinel, tags_to_dict


@register
class EC2InstanceCollector(Collector):
    service = "ec2"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ec2")
        reservations = ctx.call.paginate(
            client, "describe_instances", account_id=ctx.account_id,
            region=ctx.region, service="ec2", result_key="Reservations",
        )
        instances: list[dict[str, Any]] = []
        for res in reservations:
            instances.extend(res.get("Instances", []))
        return collect_each(instances, lambda i: self._build(ctx, i))

    def _build(self, ctx: CollectorContext, inst: dict[str, Any]) -> ResourceRecord:
        iid = inst["InstanceId"]
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"instance/{iid}")
        rec = new_record(ctx, service="ec2", resource_type="ec2:instance",
                         resource_id=iid, arn=arn)
        rec.tags = tags_to_dict(inst.get("Tags"))
        rec.availability_zone = inst.get("Placement", {}).get("AvailabilityZone", Sentinel.NA)
        rec.state_status = inst.get("State", {}).get("Name", "")
        rec.creation_date = to_iso(inst.get("LaunchTime"))
        rec.os_platform_engine = inst.get("PlatformDetails", inst.get("Platform", "Linux/UNIX"))
        rec.instance_type = inst.get("InstanceType", Sentinel.NA)
        rec.software_app = inst.get("ImageId", Sentinel.NA)
        rec.description_purpose = rec.tags.get("Name", "") or "EC2 compute instance"
        rec.source_calls = ["ec2:DescribeInstances"]

        # R3: IMDSv2 enforcement + hop limit (Req 2.2.x secure config).
        md = inst.get("MetadataOptions", {})
        if md:
            rec.imdsv2_required = md.get("HttpTokens") == "required"
            if md.get("HttpPutResponseHopLimit") is not None:
                rec.metadata_hop_limit = str(md["HttpPutResponseHopLimit"])
            if md.get("HttpEndpoint") == "disabled":
                rec.metadata_hop_limit = "endpoint-disabled"
        # In-guest controls cannot be observed read-only — mark explicitly so a
        # blank is never read as a control gap (Req 5, 10.6, 6.3.3 patch unless SSM).
        rec.anti_malware_status = Sentinel.NOT_COLLECTABLE
        rec.time_sync_source = Sentinel.NOT_COLLECTABLE
        rec.patch_compliance = Sentinel.NOT_COLLECTED  # populated by SSM patch collector if managed
        rec.vuln_scan_status = Sentinel.NOT_COLLECTED  # populated by Inspector coverage collector
        if inst.get("Monitoring", {}).get("State"):
            rec.add_note(f"detailed-monitoring={inst['Monitoring']['State']}")

        # Network / exposure.
        private_ips, public_ips, dns, enis, sgs, subnets = [], [], [], [], [], []
        for ni in inst.get("NetworkInterfaces", []):
            enis.append(ni.get("NetworkInterfaceId", ""))
            if ni.get("SubnetId"):
                subnets.append(ni["SubnetId"])
            for g in ni.get("Groups", []):
                sgs.append(g.get("GroupId", ""))
            for ip in ni.get("PrivateIpAddresses", []):
                if ip.get("PrivateIpAddress"):
                    private_ips.append(ip["PrivateIpAddress"])
                assoc = ip.get("Association", {})
                if assoc.get("PublicIp"):
                    public_ips.append(assoc["PublicIp"])
        if inst.get("PublicIpAddress"):
            public_ips.append(inst["PublicIpAddress"])
        if inst.get("PublicDnsName"):
            dns.append(inst["PublicDnsName"])
        rec.private_ips = sorted(set(private_ips))
        rec.public_ips = sorted(set(public_ips))
        rec.dns_names = sorted(set(d for d in dns if d))
        if rec.public_ips:
            add_exposure(rec, "public-ip")
        set_not_exposed_if_unset(rec)

        # Relationships.
        rec.add_relationship("enis", enis)
        rec.add_relationship("security_groups", sgs)
        rec.add_relationship("subnet", subnets)
        rec.add_relationship("vpc", inst.get("VpcId"))
        rec.add_relationship("image_id", inst.get("ImageId"))
        rec.add_relationship("key_name", inst.get("KeyName"))
        prof = inst.get("IamInstanceProfile", {})
        if prof.get("Arn"):
            rec.add_relationship("iam_instance_profile", prof["Arn"])
            rec.iam_policy_data["instance_profile_arn"] = prof["Arn"]
        vols = [bd.get("Ebs", {}).get("VolumeId") for bd in inst.get("BlockDeviceMappings", [])]
        rec.add_relationship("ebs_volumes", [v for v in vols if v])

        # EBS encryption flag is on the volume; note here that detail is per-volume.
        rec.encryption_at_rest_detail = "see attached EBS volume records"
        return rec


@register
class AMICollector(Collector):
    service = "ec2"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ec2")
        resp = ctx.call.call(
            client.describe_images, account_id=ctx.account_id, region=ctx.region,
            service="ec2", operation="DescribeImages", default={"Images": []},
            Owners=["self"],
        )
        return collect_each(resp.get("Images", []), lambda im: self._build(ctx, im))

    def _build(self, ctx: CollectorContext, im: dict[str, Any]) -> ResourceRecord:
        aid = im["ImageId"]
        client = ctx.client("ec2")
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"image/{aid}")
        rec = new_record(ctx, service="ec2", resource_type="ec2:ami",
                         resource_id=aid, arn=arn, name=im.get("Name", ""))
        rec.tags = tags_to_dict(im.get("Tags"))
        rec.state_status = im.get("State", "")
        rec.creation_date = to_iso(im.get("CreationDate"))
        rec.os_platform_engine = im.get("PlatformDetails", im.get("Platform", "Linux/UNIX"))
        rec.description_purpose = im.get("Description", "") or "Amazon Machine Image (owned)"
        rec.public_exposed = bool(im.get("Public", False))
        if rec.public_exposed:
            rec.exposure_basis.append("ami-public")
        # R1/R3: launchPermission reveals account-shared AMIs that `Public` misses.
        perm = ctx.call.call(
            client.describe_image_attribute, account_id=ctx.account_id, region=ctx.region,
            service="ec2", operation="DescribeImageAttribute", resource_id=aid, default=None,
            Attribute="launchPermission", ImageId=aid,
        )
        if perm is not None:
            launch = perm.get("LaunchPermissions", [])
            shared_accts = [p.get("UserId") for p in launch if p.get("UserId")]
            is_public = any(p.get("Group") == "all" for p in launch) or bool(im.get("Public"))
            rec.publicly_shared = is_public or bool(shared_accts)
            if is_public:
                add_exposure(rec, "ami-public")
            elif shared_accts:
                rec.add_note(f"AMI shared with accounts: {', '.join(shared_accts)}")
        else:
            # Could not read sharing — never assert not-shared.
            rec.publicly_shared = None if im.get("Public") is None else bool(im.get("Public"))
        # AMI block device encryption.
        enc = any(bd.get("Ebs", {}).get("Encrypted") for bd in im.get("BlockDeviceMappings", []))
        rec.encryption_at_rest = enc if im.get("BlockDeviceMappings") else None
        rec.source_calls = ["ec2:DescribeImages", "ec2:DescribeImageAttribute"]
        return rec


@register
class EBSVolumeCollector(Collector):
    service = "ec2"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ec2")
        vols = ctx.call.paginate(
            client, "describe_volumes", account_id=ctx.account_id,
            region=ctx.region, service="ec2", result_key="Volumes",
        )
        return collect_each(vols, lambda v: self._build(ctx, v))

    def _build(self, ctx: CollectorContext, vol: dict[str, Any]) -> ResourceRecord:
        vid = vol["VolumeId"]
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"volume/{vid}")
        rec = new_record(ctx, service="ec2", resource_type="ec2:volume",
                         resource_id=vid, arn=arn)
        rec.tags = tags_to_dict(vol.get("Tags"))
        rec.availability_zone = vol.get("AvailabilityZone", Sentinel.NA)
        rec.state_status = vol.get("State", "")
        rec.creation_date = to_iso(vol.get("CreateTime"))
        rec.encryption_at_rest = bool(vol.get("Encrypted", False))
        if vol.get("KmsKeyId"):
            rec.encryption_at_rest_detail = f"kms {vol['KmsKeyId']}"
            rec.add_relationship("kms_key", vol["KmsKeyId"])
        rec.description_purpose = rec.tags.get("Name", "") or f"EBS {vol.get('VolumeType','')} volume"
        attached = [a.get("InstanceId") for a in vol.get("Attachments", [])]
        rec.add_relationship("attached_instances", [a for a in attached if a])
        rec.public_exposed = False
        rec.source_calls = ["ec2:DescribeVolumes"]
        return rec


@register
class EBSSnapshotCollector(Collector):
    """Owned-only EBS snapshots (per user decision: include owned snapshots)."""

    service = "ec2"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ec2")
        snaps = ctx.call.paginate(
            client, "describe_snapshots", account_id=ctx.account_id,
            region=ctx.region, service="ec2", result_key="Snapshots",
            OwnerIds=["self"],
        )
        return collect_each(snaps, lambda s: self._build(ctx, s))

    def _build(self, ctx: CollectorContext, snap: dict[str, Any]) -> ResourceRecord:
        sid = snap["SnapshotId"]
        client = ctx.client("ec2")
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"snapshot/{sid}")
        rec = new_record(ctx, service="ec2", resource_type="ec2:snapshot",
                         resource_id=sid, arn=arn)
        rec.tags = tags_to_dict(snap.get("Tags"))
        rec.state_status = snap.get("State", "")
        rec.creation_date = to_iso(snap.get("StartTime"))
        rec.encryption_at_rest = bool(snap.get("Encrypted", False))
        if snap.get("KmsKeyId"):
            rec.encryption_at_rest_detail = f"kms {snap['KmsKeyId']}"
            rec.add_relationship("kms_key", snap["KmsKeyId"])
        rec.description_purpose = snap.get("Description", "") or "EBS snapshot (owned)"
        rec.add_relationship("source_volume", snap.get("VolumeId"))
        # R1: actually check createVolumePermission rather than asserting not-shared.
        perm = ctx.call.call(
            client.describe_snapshot_attribute, account_id=ctx.account_id, region=ctx.region,
            service="ec2", operation="DescribeSnapshotAttribute", resource_id=sid, default=None,
            Attribute="createVolumePermission", SnapshotId=sid,
        )
        if perm is not None:
            cvp = perm.get("CreateVolumePermissions", [])
            is_public = any(p.get("Group") == "all" for p in cvp)
            shared_accts = [p.get("UserId") for p in cvp if p.get("UserId")]
            rec.publicly_shared = is_public or bool(shared_accts)
            if is_public:
                add_exposure(rec, "snapshot-public")
            elif shared_accts:
                rec.add_note(f"snapshot shared with accounts: {', '.join(shared_accts)}")
            else:
                rec.public_exposed = False
        else:
            # Could not read sharing — leave exposure UNKNOWN rather than False.
            rec.publicly_shared = None
            rec.add_note("snapshot sharing not readable (exposure undetermined)")
        rec.source_calls = ["ec2:DescribeSnapshots", "ec2:DescribeSnapshotAttribute"]
        return rec


@register
class AutoScalingGroupCollector(Collector):
    service = "autoscaling"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("autoscaling")
        asgs = ctx.call.paginate(
            client, "describe_auto_scaling_groups", account_id=ctx.account_id,
            region=ctx.region, service="autoscaling", result_key="AutoScalingGroups",
        )
        return collect_each(asgs, lambda a: self._build(ctx, a))

    def _build(self, ctx: CollectorContext, asg: dict[str, Any]) -> ResourceRecord:
        arn = asg.get("AutoScalingGroupARN", "")
        name = asg.get("AutoScalingGroupName", "")
        rec = new_record(ctx, service="autoscaling", resource_type="autoscaling:group",
                         resource_id=name, arn=arn or synth_arn("autoscaling", ctx.region, ctx.account_id, f"autoScalingGroup/{name}"),
                         name=name)
        rec.tags = tags_to_dict(asg.get("Tags"))
        rec.creation_date = to_iso(asg.get("CreatedTime"))
        rec.state_status = f"desired={asg.get('DesiredCapacity')} min={asg.get('MinSize')} max={asg.get('MaxSize')}"
        rec.description_purpose = "Auto Scaling group"
        rec.add_relationship("instances", [i.get("InstanceId") for i in asg.get("Instances", [])])
        rec.add_relationship("subnets", (asg.get("VPCZoneIdentifier", "") or "").split(",") if asg.get("VPCZoneIdentifier") else [])
        lt = asg.get("LaunchTemplate") or asg.get("MixedInstancesPolicy", {}).get("LaunchTemplate", {}).get("LaunchTemplateSpecification", {})
        if lt.get("LaunchTemplateId"):
            rec.add_relationship("launch_template", lt["LaunchTemplateId"])
        if asg.get("LaunchConfigurationName"):
            rec.add_relationship("launch_configuration", asg["LaunchConfigurationName"])
        rec.public_exposed = False
        rec.source_calls = ["autoscaling:DescribeAutoScalingGroups"]
        return rec


@register
class LaunchTemplateCollector(Collector):
    service = "ec2"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ec2")
        lts = ctx.call.paginate(
            client, "describe_launch_templates", account_id=ctx.account_id,
            region=ctx.region, service="ec2", result_key="LaunchTemplates",
        )
        return collect_each(lts, lambda t: self._build(ctx, t))

    def _build(self, ctx: CollectorContext, lt: dict[str, Any]) -> ResourceRecord:
        lid = lt["LaunchTemplateId"]
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"launch-template/{lid}")
        rec = new_record(ctx, service="ec2", resource_type="ec2:launch-template",
                         resource_id=lid, arn=arn, name=lt.get("LaunchTemplateName", ""))
        rec.tags = tags_to_dict(lt.get("Tags"))
        rec.creation_date = to_iso(lt.get("CreateTime"))
        rec.state_status = f"latest=v{lt.get('LatestVersionNumber')}"
        rec.description_purpose = "EC2 launch template"
        rec.public_exposed = False
        rec.source_calls = ["ec2:DescribeLaunchTemplates"]
        return rec


@register
class LaunchConfigurationCollector(Collector):
    service = "autoscaling"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("autoscaling")
        lcs = ctx.call.paginate(
            client, "describe_launch_configurations", account_id=ctx.account_id,
            region=ctx.region, service="autoscaling", result_key="LaunchConfigurations",
        )
        return collect_each(lcs, lambda c: self._build(ctx, c))

    def _build(self, ctx: CollectorContext, lc: dict[str, Any]) -> ResourceRecord:
        name = lc["LaunchConfigurationName"]
        arn = lc.get("LaunchConfigurationARN", "") or synth_arn("autoscaling", ctx.region, ctx.account_id, f"launchConfiguration/{name}")
        rec = new_record(ctx, service="autoscaling", resource_type="autoscaling:launch-configuration",
                         resource_id=name, arn=arn, name=name)
        rec.creation_date = to_iso(lc.get("CreatedTime"))
        rec.os_platform_engine = lc.get("ImageId", Sentinel.NA)
        rec.public_exposed = bool(lc.get("AssociatePublicIpAddress", False))
        if rec.public_exposed:
            rec.exposure_basis.append("associate-public-ip")
        rec.add_relationship("security_groups", lc.get("SecurityGroups", []))
        rec.description_purpose = "EC2 launch configuration (legacy)"
        rec.source_calls = ["autoscaling:DescribeLaunchConfigurations"]
        return rec


@register
class LambdaCollector(Collector):
    service = "lambda"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("lambda")
        fns = ctx.call.paginate(
            client, "list_functions", account_id=ctx.account_id,
            region=ctx.region, service="lambda", result_key="Functions",
        )
        out = []
        for fn in fns:
            try:
                out.append(self._build(ctx, client, fn))
            except Exception:  # noqa: BLE001
                continue
        return out

    def _build(self, ctx: CollectorContext, client: Any, fn: dict[str, Any]) -> ResourceRecord:
        arn = fn["FunctionArn"]
        name = fn["FunctionName"]
        rec = new_record(ctx, service="lambda", resource_type="lambda:function",
                         resource_id=name, arn=arn, name=name)
        rec.os_platform_engine = fn.get("Runtime", "container/image")
        rec.software_app = name
        rec.software_version = fn.get("Version", "")
        rec.is_bespoke_software = True  # Lambda runs customer code.
        rec.last_modified_activity = to_iso(fn.get("LastModified"))
        rec.description_purpose = fn.get("Description", "") or "Lambda function (bespoke code)"
        rec.encryption_at_rest = True if fn.get("KMSKeyArn") else None
        if fn.get("KMSKeyArn"):
            rec.encryption_at_rest_detail = f"kms {fn['KMSKeyArn']}"
            rec.add_relationship("kms_key", fn["KMSKeyArn"])
        rec.add_relationship("execution_role", fn.get("Role"))
        rec.iam_policy_data["execution_role"] = fn.get("Role")
        vpc = fn.get("VpcConfig", {})
        if vpc.get("VpcId"):
            rec.add_relationship("vpc", vpc.get("VpcId"))
            rec.add_relationship("subnets", vpc.get("SubnetIds", []))
            rec.add_relationship("security_groups", vpc.get("SecurityGroupIds", []))
        rec.add_relationship("layers", [layer.get("Arn") for layer in fn.get("Layers", [])])
        rec.source_calls = ["lambda:ListFunctions"]

        # Resource policy (function URL / public invoke) — exposure + Stage 2 graph.
        pol = ctx.call.call(
            client.get_policy, account_id=ctx.account_id, region=ctx.region,
            service="lambda", operation="GetPolicy", resource_id=name, default=None,
            FunctionName=name,
        )
        if pol and pol.get("Policy"):
            assess_resource_policy_exposure(rec, pol["Policy"], "lambda-resource-policy")
        # Function URL config (if any) is public unless IAM-authed.
        url_cfg = ctx.call.call(
            client.get_function_url_config, account_id=ctx.account_id, region=ctx.region,
            service="lambda", operation="GetFunctionUrlConfig", resource_id=name, default=None,
            FunctionName=name,
        )
        if url_cfg and url_cfg.get("FunctionUrl"):
            rec.dns_names.append(url_cfg["FunctionUrl"])
            if url_cfg.get("AuthType") == "NONE":
                add_exposure(rec, "lambda-function-url-public")
        set_not_exposed_if_unset(rec)
        return rec


@register
class ECSCollector(Collector):
    service = "ecs"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ecs")
        records: list[ResourceRecord] = []
        cluster_arns = list(ctx.call.paginate(
            client, "list_clusters", account_id=ctx.account_id,
            region=ctx.region, service="ecs", result_key="clusterArns",
        ))
        if not cluster_arns:
            return records
        desc = ctx.call.call(
            client.describe_clusters, account_id=ctx.account_id, region=ctx.region,
            service="ecs", operation="DescribeClusters", default={"clusters": []},
            clusters=cluster_arns, include=["TAGS", "SETTINGS"],
        )
        for cl in desc.get("clusters", []):
            arn = cl["clusterArn"]
            name = cl.get("clusterName", "")
            rec = new_record(ctx, service="ecs", resource_type="ecs:cluster",
                             resource_id=name, arn=arn, name=name)
            rec.tags = tags_to_dict(cl.get("tags"))
            rec.state_status = cl.get("status", "")
            rec.is_bespoke_software = True
            rec.description_purpose = "ECS cluster (containerized workloads)"
            rec.state_status = f"{cl.get('status','')} services={cl.get('activeServicesCount',0)} tasks={cl.get('runningTasksCount',0)}"
            rec.public_exposed = False
            rec.source_calls = ["ecs:ListClusters", "ecs:DescribeClusters"]
            records.append(rec)
        return records


@register
class EKSCollector(Collector):
    service = "eks"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("eks")
        names = list(ctx.call.paginate(
            client, "list_clusters", account_id=ctx.account_id,
            region=ctx.region, service="eks", result_key="clusters",
        ))
        def build(name: str) -> ResourceRecord | None:
            desc = ctx.call.call(
                client.describe_cluster, account_id=ctx.account_id, region=ctx.region,
                service="eks", operation="DescribeCluster", resource_id=name, default=None,
                name=name,
            )
            if not desc or "cluster" not in desc:
                return None
            cl = desc["cluster"]
            rec = new_record(ctx, service="eks", resource_type="eks:cluster",
                             resource_id=name, arn=cl.get("arn", ""), name=name)
            rec.tags = dict(cl.get("tags", {}))
            rec.os_platform_engine = "kubernetes"
            rec.os_platform_version = cl.get("version", "")
            rec.state_status = cl.get("status", "")
            rec.creation_date = to_iso(cl.get("createdAt"))
            rec.is_bespoke_software = True
            rec.description_purpose = "EKS Kubernetes cluster"
            res_vpc = cl.get("resourcesVpcConfig", {})
            rec.add_relationship("vpc", res_vpc.get("vpcId"))
            rec.add_relationship("subnets", res_vpc.get("subnetIds", []))
            rec.add_relationship("security_groups", res_vpc.get("securityGroupIds", []))
            rec.add_relationship("execution_role", cl.get("roleArn"))
            if res_vpc.get("endpointPublicAccess"):
                cidrs = res_vpc.get("publicAccessCidrs", [])
                if "0.0.0.0/0" in cidrs or not cidrs:
                    add_exposure(rec, "eks-public-endpoint-open")
                else:
                    add_exposure(rec, f"eks-public-endpoint ({','.join(cidrs)})")
            # R3: control-plane audit logging (Req 10).
            log_types = []
            for lg in cl.get("logging", {}).get("clusterLogging", []):
                if lg.get("enabled"):
                    log_types.extend(lg.get("types", []))
            rec.logging_enabled = bool(log_types)
            rec.logging_detail = "control-plane: " + ", ".join(log_types) if log_types else "no control-plane logging"
            if "audit" not in log_types:
                rec.add_note("EKS audit logging not enabled (review 10.2)")
            if cl.get("endpoint"):
                rec.dns_names.append(cl["endpoint"])
            enc = cl.get("encryptionConfig")
            rec.encryption_at_rest = bool(enc) if enc is not None else None
            set_not_exposed_if_unset(rec)
            rec.source_calls = ["eks:ListClusters", "eks:DescribeCluster"]
            return rec

        return collect_each(names, build)


@register
class ECRCollector(Collector):
    service = "ecr"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ecr")
        repos = ctx.call.paginate(
            client, "describe_repositories", account_id=ctx.account_id,
            region=ctx.region, service="ecr", result_key="repositories",
        )
        return collect_each(repos, lambda r: self._build(ctx, client, r))

    def _build(self, ctx: CollectorContext, client: Any, repo: dict[str, Any]) -> ResourceRecord:
        arn = repo["repositoryArn"]
        name = repo["repositoryName"]
        rec = new_record(ctx, service="ecr", resource_type="ecr:repository",
                         resource_id=name, arn=arn, name=name)
        rec.creation_date = to_iso(repo.get("createdAt"))
        rec.is_bespoke_software = True
        rec.description_purpose = "ECR container image repository"
        enc = repo.get("encryptionConfiguration", {})
        rec.encryption_at_rest = True if enc else None
        rec.encryption_at_rest_detail = enc.get("encryptionType", "")
        rec.dns_names = [repo.get("repositoryUri", "")] if repo.get("repositoryUri") else []
        rec.state_status = repo.get("imageTagMutability", "")
        # R4: image scanning config — scan-on-push for vulnerability detection (Req 6.3.1/11.3).
        scan_cfg = repo.get("imageScanningConfiguration", {})
        if scan_cfg.get("scanOnPush"):
            rec.vuln_scan_status = "scan-on-push"
        else:
            rec.vuln_scan_status = "no-scan-on-push"
            rec.add_note("ECR scan-on-push disabled (review 6.3.1)")
        # Repository policy → public exposure signal + Stage 2 graph.
        pol = ctx.call.call(
            client.get_repository_policy, account_id=ctx.account_id, region=ctx.region,
            service="ecr", operation="GetRepositoryPolicy", resource_id=name, default=None,
            repositoryName=name,
        )
        if pol and pol.get("policyText"):
            assess_resource_policy_exposure(rec, pol["policyText"], "ecr-repository-policy")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["ecr:DescribeRepositories", "ecr:GetRepositoryPolicy"]
        return rec


@register
class BatchCollector(Collector):
    service = "batch"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("batch")
        resp = ctx.call.call(
            client.describe_compute_environments, account_id=ctx.account_id,
            region=ctx.region, service="batch", operation="DescribeComputeEnvironments",
            default={"computeEnvironments": []},
        )
        records = collect_each(resp.get("computeEnvironments", []),
                               lambda c: self._build_env(ctx, c))
        return records

    def _build_env(self, ctx: CollectorContext, env: dict[str, Any]) -> ResourceRecord:
        arn = env["computeEnvironmentArn"]
        name = env["computeEnvironmentName"]
        rec = new_record(ctx, service="batch", resource_type="batch:compute-environment",
                         resource_id=name, arn=arn, name=name)
        rec.state_status = env.get("status", "")
        rec.description_purpose = "AWS Batch compute environment"
        cr = env.get("computeResources", {})
        rec.add_relationship("subnets", cr.get("subnets", []))
        rec.add_relationship("security_groups", cr.get("securityGroupIds", []))
        rec.public_exposed = False
        rec.source_calls = ["batch:DescribeComputeEnvironments"]
        return rec


@register
class LightsailCollector(Collector):
    service = "lightsail"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("lightsail")
        resp = ctx.call.call(
            client.get_instances, account_id=ctx.account_id, region=ctx.region,
            service="lightsail", operation="GetInstances", default={"instances": []},
        )
        return collect_each(resp.get("instances", []), lambda i: self._build(ctx, i))

    def _build(self, ctx: CollectorContext, inst: dict[str, Any]) -> ResourceRecord:
        arn = inst.get("arn", "")
        name = inst.get("name", "")
        rec = new_record(ctx, service="lightsail", resource_type="lightsail:instance",
                         resource_id=name, arn=arn, name=name)
        rec.tags = tags_to_dict(inst.get("tags"))
        rec.availability_zone = inst.get("location", {}).get("availabilityZone", Sentinel.NA)
        rec.state_status = inst.get("state", {}).get("name", "")
        rec.creation_date = to_iso(inst.get("createdAt"))
        rec.os_platform_engine = inst.get("blueprintName", "")
        if inst.get("publicIpAddress"):
            rec.public_ips = [inst["publicIpAddress"]]
            add_exposure(rec, "public-ip")
        if inst.get("privateIpAddress"):
            rec.private_ips = [inst["privateIpAddress"]]
        rec.description_purpose = "Lightsail instance"
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["lightsail:GetInstances"]
        return rec


@register
class ElasticBeanstalkCollector(Collector):
    service = "elasticbeanstalk"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("elasticbeanstalk")
        resp = ctx.call.call(
            client.describe_environments, account_id=ctx.account_id, region=ctx.region,
            service="elasticbeanstalk", operation="DescribeEnvironments",
            default={"Environments": []},
        )
        return collect_each(resp.get("Environments", []), lambda e: self._build(ctx, e))

    def _build(self, ctx: CollectorContext, env: dict[str, Any]) -> ResourceRecord:
        arn = env.get("EnvironmentArn", "")
        name = env.get("EnvironmentName", "")
        rec = new_record(ctx, service="elasticbeanstalk", resource_type="elasticbeanstalk:environment",
                         resource_id=env.get("EnvironmentId", name), arn=arn, name=name)
        rec.state_status = env.get("Status", "")
        rec.os_platform_engine = env.get("PlatformArn", env.get("SolutionStackName", ""))
        rec.software_app = env.get("ApplicationName", "")
        rec.software_version = env.get("VersionLabel", "")
        rec.is_bespoke_software = True
        rec.creation_date = to_iso(env.get("DateCreated"))
        rec.last_modified_activity = to_iso(env.get("DateUpdated"))
        rec.description_purpose = env.get("Description", "") or "Elastic Beanstalk environment"
        if env.get("CNAME"):
            rec.dns_names = [env["CNAME"]]
        if env.get("EndpointURL"):
            # Beanstalk envs are typically internet-facing unless in a private VPC.
            add_exposure(rec, "beanstalk-endpoint")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["elasticbeanstalk:DescribeEnvironments"]
        return rec
