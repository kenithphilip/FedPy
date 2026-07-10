"""Database collectors: RDS/Aurora (incl. DocumentDB & Neptune via the RDS API),
DynamoDB, ElastiCache, Redshift, MemoryDB, Timestream, QLDB.

Records capture encryption-at-rest, in-transit (where exposed), public
accessibility, engine + version (for EOL/patch analysis), and network
relationships (subnet group, security groups, VPC).
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
from pci_inventory.utils import Sentinel, tags_to_dict

# Parameter names that, when set to "1"/"true", enforce TLS for DB connections.
_FORCE_SSL_PARAMS = {"rds.force_ssl", "require_secure_transport"}


def _force_ssl_from_param_groups(ctx: CollectorContext, group_names: list[str | None],
                                 cluster: bool = False) -> bool | None:
    """Return True if any named (cluster) parameter group forces TLS, else False/None.

    Returns None when no group could be read (so the column stays N/A rather than
    falsely asserting plaintext is allowed). Best-effort and read-only.
    """
    client = ctx.client("rds")
    op = "describe_db_cluster_parameters" if cluster else "describe_db_parameters"
    name_arg = "DBClusterParameterGroupName" if cluster else "DBParameterGroupName"
    any_read = False
    for gname in [g for g in group_names if g]:
        params = ctx.call.paginate(
            client, op, account_id=ctx.account_id, region=ctx.region,
            service="rds", result_key="Parameters", **{name_arg: gname},
        )
        for p in params:
            any_read = True
            if p.get("ParameterName") in _FORCE_SSL_PARAMS:
                val = str(p.get("ParameterValue", "")).lower()
                if val in ("1", "true", "on"):
                    return True
    return False if any_read else None


@register
class RDSInstanceCollector(Collector):
    service = "rds"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("rds")
        dbs = ctx.call.paginate(client, "describe_db_instances", account_id=ctx.account_id,
                                region=ctx.region, service="rds", result_key="DBInstances")
        return collect_each(dbs, lambda d: self._build(ctx, d))

    def _build(self, ctx: CollectorContext, db: dict[str, Any]) -> ResourceRecord:
        ident = db["DBInstanceIdentifier"]
        arn = db.get("DBInstanceArn", "")
        engine = db.get("Engine", "")
        # Classify DocumentDB/Neptune which share the RDS API surface.
        if engine.startswith("docdb"):
            service, rtype = "docdb", "docdb:instance"
        elif engine.startswith("neptune"):
            service, rtype = "neptune", "neptune:instance"
        else:
            service, rtype = "rds", "rds:db-instance"
        rec = new_record(ctx, service=service, resource_type=rtype,
                         resource_id=ident, arn=arn, name=ident)
        rec.tags = tags_to_dict(db.get("TagList"))
        rec.availability_zone = db.get("AvailabilityZone", Sentinel.NA)
        rec.state_status = db.get("DBInstanceStatus", "")
        rec.creation_date = to_iso(db.get("InstanceCreateTime"))
        rec.os_platform_engine = engine
        rec.os_platform_version = db.get("EngineVersion", "")
        rec.instance_type = db.get("DBInstanceClass", Sentinel.NA)
        rec.encryption_at_rest = bool(db.get("StorageEncrypted", False))
        if db.get("KmsKeyId"):
            rec.encryption_at_rest_detail = f"kms {db['KmsKeyId']}"
            rec.add_relationship("kms_key", db["KmsKeyId"])
        rec.backup_config = f"{db.get('BackupRetentionPeriod', 0)} days"
        if db.get("MultiAZ"):
            rec.backup_config += "; MultiAZ"
        rec.description_purpose = f"{engine} database instance"

        # R3: PCI-relevant DB config flags.
        rec.deletion_protection = bool(db.get("DeletionProtection", False))
        rec.auto_minor_version_upgrade = bool(db.get("AutoMinorVersionUpgrade", False))
        rec.iam_db_auth = bool(db.get("IAMDatabaseAuthenticationEnabled", False))
        if db.get("CACertificateIdentifier"):
            rec.add_note(f"CA cert: {db['CACertificateIdentifier']}")
        if db.get("EnabledCloudwatchLogsExports"):
            rec.logging_enabled = True
            rec.logging_detail = "cw-logs: " + ", ".join(db["EnabledCloudwatchLogsExports"])

        endpoint = db.get("Endpoint", {})
        if endpoint.get("Address"):
            rec.dns_names = [endpoint["Address"]]
        if db.get("PubliclyAccessible"):
            add_exposure(rec, "rds-publicly-accessible (flag; reachability pending Stage 2)")
        rec.add_relationship("vpc", db.get("DBSubnetGroup", {}).get("VpcId"))
        rec.add_relationship("subnet_group", db.get("DBSubnetGroup", {}).get("DBSubnetGroupName"))
        rec.add_relationship("security_groups", [g.get("VpcSecurityGroupId") for g in db.get("VpcSecurityGroups", [])])
        if db.get("DBClusterIdentifier"):
            rec.add_relationship("cluster", db["DBClusterIdentifier"])
        # R3: forced-TLS via parameter group (rds.force_ssl / require_secure_transport).
        pg_names = [pg.get("DBParameterGroupName") for pg in db.get("DBParameterGroups", [])]
        rec.encryption_in_transit = _force_ssl_from_param_groups(ctx, pg_names)
        if rec.encryption_in_transit:
            rec.encryption_in_transit_detail = "forced via parameter group"
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["rds:DescribeDBInstances", "rds:DescribeDBParameters"]
        return rec


@register
class RDSClusterCollector(Collector):
    service = "rds"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("rds")
        clusters = ctx.call.paginate(client, "describe_db_clusters", account_id=ctx.account_id,
                                     region=ctx.region, service="rds", result_key="DBClusters")
        return collect_each(clusters, lambda c: self._build(ctx, c))

    def _build(self, ctx: CollectorContext, c: dict[str, Any]) -> ResourceRecord:
        ident = c["DBClusterIdentifier"]
        engine = c.get("Engine", "")
        if engine.startswith("docdb"):
            service, rtype = "docdb", "docdb:cluster"
        elif engine.startswith("neptune"):
            service, rtype = "neptune", "neptune:cluster"
        else:
            service, rtype = "rds", "rds:db-cluster"
        rec = new_record(ctx, service=service, resource_type=rtype,
                         resource_id=ident, arn=c.get("DBClusterArn", ""), name=ident)
        rec.tags = tags_to_dict(c.get("TagList"))
        rec.state_status = c.get("Status", "")
        rec.creation_date = to_iso(c.get("ClusterCreateTime"))
        rec.os_platform_engine = engine
        rec.os_platform_version = c.get("EngineVersion", "")
        rec.encryption_at_rest = bool(c.get("StorageEncrypted", False))
        if c.get("KmsKeyId"):
            rec.encryption_at_rest_detail = f"kms {c['KmsKeyId']}"
            rec.add_relationship("kms_key", c["KmsKeyId"])
        rec.backup_config = f"{c.get('BackupRetentionPeriod', 0)} days"
        rec.description_purpose = f"{engine} database cluster"
        if c.get("EngineMode"):
            rec.state_status = f"{c.get('Status','')} ({c['EngineMode']})"  # serverless detection
        for ep_key in ("Endpoint", "ReaderEndpoint"):
            if c.get(ep_key):
                rec.dns_names.append(c[ep_key])
        # M1 fix: describe_db_clusters does NOT return PubliclyAccessible (it is a
        # per-instance attribute). Exposure is derived from member instances'
        # records instead; do not assert a (always-false) cluster-level flag here.
        rec.public_exposed = None
        rec.add_note("cluster exposure derived from member instances (see rds:db-instance rows)")
        rec.deletion_protection = bool(c.get("DeletionProtection", False))
        rec.iam_db_auth = bool(c.get("IAMDatabaseAuthenticationEnabled", False))
        if c.get("EnabledCloudwatchLogsExports"):
            rec.logging_enabled = True
            rec.logging_detail = "cw-logs: " + ", ".join(c["EnabledCloudwatchLogsExports"])
        rec.add_relationship("vpc", c.get("DbSubnetGroup"))
        rec.add_relationship("cluster_members", [m.get("DBInstanceIdentifier") for m in c.get("DBClusterMembers", [])])
        rec.add_relationship("security_groups", [g.get("VpcSecurityGroupId") for g in c.get("VpcSecurityGroups", [])])
        # Forced-TLS via cluster parameter group.
        pg = c.get("DBClusterParameterGroup")
        rec.encryption_in_transit = _force_ssl_from_param_groups(ctx, [pg], cluster=True) if pg else None
        rec.source_calls = ["rds:DescribeDBClusters", "rds:DescribeDBClusterParameters"]
        return rec


@register
class DynamoDBCollector(Collector):
    service = "dynamodb"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("dynamodb")
        names = list(ctx.call.paginate(client, "list_tables", account_id=ctx.account_id,
                                       region=ctx.region, service="dynamodb", result_key="TableNames"))
        out: list[ResourceRecord] = []
        for name in names:
            desc = ctx.call.call(client.describe_table, account_id=ctx.account_id, region=ctx.region,
                                 service="dynamodb", operation="DescribeTable", resource_id=name,
                                 default=None, TableName=name)
            if not desc:
                continue
            t = desc["Table"]
            rec = new_record(ctx, service="dynamodb", resource_type="dynamodb:table",
                             resource_id=name, arn=t.get("TableArn", ""), name=name)
            rec.state_status = t.get("TableStatus", "")
            rec.creation_date = to_iso(t.get("CreationDateTime"))
            sse = t.get("SSEDescription", {})
            # DynamoDB is always encrypted at rest (AWS-owned key by default).
            rec.encryption_at_rest = True
            rec.encryption_at_rest_detail = sse.get("SSEType", "AWS-owned key")
            if sse.get("KMSMasterKeyArn"):
                rec.add_relationship("kms_key", sse["KMSMasterKeyArn"])
            rec.description_purpose = "DynamoDB table"
            rec.public_exposed = False
            rec.source_calls = ["dynamodb:ListTables", "dynamodb:DescribeTable"]
            out.append(rec)
        return out


@register
class ElastiCacheCollector(Collector):
    service = "elasticache"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("elasticache")
        clusters = ctx.call.paginate(client, "describe_cache_clusters", account_id=ctx.account_id,
                                     region=ctx.region, service="elasticache", result_key="CacheClusters")
        return collect_each(clusters, lambda c: self._build(ctx, c))

    def _build(self, ctx: CollectorContext, c: dict[str, Any]) -> ResourceRecord:
        cid = c["CacheClusterId"]
        rec = new_record(ctx, service="elasticache", resource_type="elasticache:cluster",
                         resource_id=cid, arn=c.get("ARN", ""), name=cid)
        rec.state_status = c.get("CacheClusterStatus", "")
        rec.os_platform_engine = c.get("Engine", "")
        rec.os_platform_version = c.get("EngineVersion", "")
        rec.creation_date = to_iso(c.get("CacheClusterCreateTime"))
        rec.encryption_at_rest = bool(c.get("AtRestEncryptionEnabled", False))
        rec.encryption_in_transit = bool(c.get("TransitEncryptionEnabled", False))
        rec.availability_zone = c.get("PreferredAvailabilityZone", Sentinel.NA)
        rec.description_purpose = f"ElastiCache {c.get('Engine','')} cluster"
        rec.add_relationship("security_groups", [g.get("SecurityGroupId") for g in c.get("SecurityGroups", [])])
        rec.public_exposed = False
        rec.source_calls = ["elasticache:DescribeCacheClusters"]
        return rec


@register
class RedshiftCollector(Collector):
    service = "redshift"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("redshift")
        clusters = ctx.call.paginate(client, "describe_clusters", account_id=ctx.account_id,
                                     region=ctx.region, service="redshift", result_key="Clusters")
        return collect_each(clusters, lambda c: self._build(ctx, c))

    def _build(self, ctx: CollectorContext, c: dict[str, Any]) -> ResourceRecord:
        cid = c["ClusterIdentifier"]
        arn = synth_arn("redshift", ctx.region, ctx.account_id, f"cluster:{cid}")
        rec = new_record(ctx, service="redshift", resource_type="redshift:cluster",
                         resource_id=cid, arn=arn, name=cid)
        rec.tags = tags_to_dict(c.get("Tags"))
        rec.state_status = c.get("ClusterStatus", "")
        rec.availability_zone = c.get("AvailabilityZone", Sentinel.NA)
        rec.creation_date = to_iso(c.get("ClusterCreateTime"))
        rec.os_platform_engine = "redshift"
        rec.os_platform_version = c.get("ClusterVersion", "")
        rec.encryption_at_rest = bool(c.get("Encrypted", False))
        if c.get("KmsKeyId"):
            rec.add_relationship("kms_key", c["KmsKeyId"])
        rec.description_purpose = "Redshift data warehouse cluster"
        if c.get("Endpoint", {}).get("Address"):
            rec.dns_names = [c["Endpoint"]["Address"]]
        if c.get("PubliclyAccessible"):
            add_exposure(rec, "redshift-publicly-accessible")
        rec.add_relationship("vpc", c.get("VpcId"))
        rec.add_relationship("security_groups", [g.get("VpcSecurityGroupId") for g in c.get("VpcSecurityGroups", [])])
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["redshift:DescribeClusters"]
        return rec


@register
class MemoryDBCollector(Collector):
    service = "memorydb"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("memorydb")
        clusters = ctx.call.paginate(client, "describe_clusters", account_id=ctx.account_id,
                                     region=ctx.region, service="memorydb", result_key="Clusters")
        return collect_each(clusters, lambda c: self._build(ctx, c))

    def _build(self, ctx: CollectorContext, c: dict[str, Any]) -> ResourceRecord:
        name = c["Name"]
        rec = new_record(ctx, service="memorydb", resource_type="memorydb:cluster",
                         resource_id=name, arn=c.get("ARN", ""), name=name)
        rec.state_status = c.get("Status", "")
        rec.os_platform_engine = "redis"
        rec.os_platform_version = c.get("EngineVersion", "")
        rec.encryption_at_rest = bool(c.get("KmsKeyId"))
        if c.get("KmsKeyId"):
            rec.add_relationship("kms_key", c["KmsKeyId"])
        rec.encryption_in_transit = bool(c.get("TLSEnabled", False))
        rec.description_purpose = "MemoryDB for Redis cluster"
        rec.public_exposed = False
        rec.source_calls = ["memorydb:DescribeClusters"]
        return rec


@register
class TimestreamCollector(Collector):
    service = "timestream"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        # timestream-write is the control plane for databases/tables.
        client = ctx.client("timestream-write")
        dbs = ctx.call.paginate(client, "list_databases", account_id=ctx.account_id,
                                region=ctx.region, service="timestream", result_key="Databases")
        return collect_each(dbs, lambda d: self._build(ctx, d))

    def _build(self, ctx: CollectorContext, d: dict[str, Any]) -> ResourceRecord:
        name = d["DatabaseName"]
        rec = new_record(ctx, service="timestream", resource_type="timestream:database",
                         resource_id=name, arn=d.get("Arn", ""), name=name)
        rec.creation_date = to_iso(d.get("CreationTime"))
        rec.last_modified_activity = to_iso(d.get("LastUpdatedTime"))
        rec.encryption_at_rest = True  # always KMS-encrypted
        if d.get("KmsKeyId"):
            rec.add_relationship("kms_key", d["KmsKeyId"])
        rec.description_purpose = "Timestream database"
        rec.public_exposed = False
        rec.source_calls = ["timestream-write:ListDatabases"]
        return rec


@register
class QLDBCollector(Collector):
    service = "qldb"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("qldb")
        ledgers = ctx.call.paginate(client, "list_ledgers", account_id=ctx.account_id,
                                    region=ctx.region, service="qldb", result_key="Ledgers")
        out = []
        for ledger in ledgers:
            name = ledger["Name"]
            desc = ctx.call.call(client.describe_ledger, account_id=ctx.account_id, region=ctx.region,
                                 service="qldb", operation="DescribeLedger", resource_id=name,
                                 default=None, Name=name)
            d = desc or ledger
            rec = new_record(ctx, service="qldb", resource_type="qldb:ledger",
                             resource_id=name, arn=d.get("Arn", ""), name=name)
            rec.state_status = d.get("State", "")
            rec.creation_date = to_iso(d.get("CreationDateTime"))
            rec.encryption_at_rest = True
            enc = d.get("EncryptionDescription", {})
            if enc.get("KmsKeyArn"):
                rec.add_relationship("kms_key", enc["KmsKeyArn"])
            rec.description_purpose = "QLDB ledger"
            rec.public_exposed = False
            rec.source_calls = ["qldb:ListLedgers", "qldb:DescribeLedger"]
            out.append(rec)
        return out
