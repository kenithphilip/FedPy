"""Logging & monitoring collectors: CloudTrail trails (+ multi-region/validation/
KMS), CloudWatch Log groups (+ retention/metric filters), CloudWatch Alarms,
Config recorders/rules/conformance packs, EventBridge rules/buses.

These records support Requirement 10 (audit logging) and are inputs to Stage 3's
control checks. Config and CloudTrail throttle hard, so they are in the
hard-throttle service class.
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


@register
class CloudTrailCollector(Collector):
    service = "cloudtrail"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("cloudtrail")
        # R1: includeShadowTrails=True so org/multi-region trails are visible in
        # member/other regions; we then dedup by ARN + emit only in home region.
        resp = ctx.call.call(client.describe_trails, account_id=ctx.account_id, region=ctx.region,
                             service="cloudtrail", operation="DescribeTrails",
                             default={"trailList": []}, includeShadowTrails=True)
        out = []
        for t in resp.get("trailList", []):
            # Only emit a trail in its home region to avoid duplicates for
            # multi-region/org trails (describe returns them in every region).
            if t.get("HomeRegion") and t.get("HomeRegion") != ctx.region:
                continue
            name = t.get("Name", "")
            rec = new_record(ctx, service="cloudtrail", resource_type="cloudtrail:trail",
                             resource_id=name, arn=t.get("TrailARN", ""), name=name)
            rec.description_purpose = "CloudTrail trail (management/data event logging)"
            rec.encryption_at_rest = bool(t.get("KmsKeyId"))
            if t.get("KmsKeyId"):
                rec.add_relationship("kms_key", t["KmsKeyId"])
            multi = t.get("IsMultiRegionTrail", False)
            validation = t.get("LogFileValidationEnabled", False)
            is_org = t.get("IsOrganizationTrail", False)
            rec.state_status = f"multi_region={multi} log_validation={validation} org={is_org}"
            rec.add_relationship("s3_bucket", t.get("S3BucketName"))
            rec.add_relationship("cw_log_group", t.get("CloudWatchLogsLogGroupArn"))

            # Trail status: is logging actually on?
            status = ctx.call.call(client.get_trail_status, account_id=ctx.account_id, region=ctx.region,
                                   service="cloudtrail", operation="GetTrailStatus", resource_id=name,
                                   default={}, Name=t.get("TrailARN", name))
            rec.logging_enabled = bool(status.get("IsLogging"))
            rec.last_modified_activity = to_iso(status.get("LatestDeliveryTime"))

            # R3: event selectors — is management + data event logging actually on?
            mgmt_events, data_events, rw_type = self._event_selectors(ctx, client, t.get("TrailARN", name))
            rec.logging_detail = (f"s3={t.get('S3BucketName','')} multi_region={multi} org={is_org} "
                                  f"validation={validation} kms={'yes' if t.get('KmsKeyId') else 'no'} "
                                  f"mgmt_events={mgmt_events}({rw_type}) data_event_selectors={data_events}")
            if not multi and not is_org:
                rec.add_note("trail is single-region (review 10.2 coverage)")
            if not validation:
                rec.add_note("log file validation disabled (review 10.3.x)")
            if not mgmt_events:
                rec.add_note("management events not logged (review 10.2.1)")
            rec.public_exposed = False
            rec.source_calls = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
                                "cloudtrail:GetEventSelectors"]
            out.append(rec)
        return out

    def _event_selectors(self, ctx: CollectorContext, client: Any, trail_arn: str):
        """Return (mgmt_events_on: bool, data_event_selector_count: int, rw_type: str)."""
        sel = ctx.call.call(client.get_event_selectors, account_id=ctx.account_id, region=ctx.region,
                            service="cloudtrail", operation="GetEventSelectors", resource_id=trail_arn,
                            default=None, TrailName=trail_arn)
        if not sel:
            return False, 0, "unknown"
        mgmt = False
        data_count = 0
        rw = "None"
        for s in sel.get("EventSelectors", []):
            if s.get("IncludeManagementEvents"):
                mgmt = True
                rw = s.get("ReadWriteType", rw)
            data_count += len(s.get("DataResources", []))
        # Advanced event selectors (newer API form).
        for s in sel.get("AdvancedEventSelectors", []):
            fields = {f.get("Field") for f in s.get("FieldSelectors", [])}
            if "eventCategory" in fields:
                mgmt = True
                data_count += 1
        return mgmt, data_count, rw


@register
class CloudWatchLogsCollector(Collector):
    service = "logs"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("logs")
        groups = ctx.call.paginate(client, "describe_log_groups", account_id=ctx.account_id,
                                   region=ctx.region, service="logs", result_key="logGroups")
        return collect_each(groups, lambda g: self._build(ctx, g))

    def _build(self, ctx: CollectorContext, g: dict[str, Any]) -> ResourceRecord:
        name = g["logGroupName"]
        rec = new_record(ctx, service="logs", resource_type="logs:log-group",
                         resource_id=name, arn=g.get("arn", ""), name=name)
        rec.creation_date = to_iso(_ms(g.get("creationTime")))
        rec.encryption_at_rest = bool(g.get("kmsKeyId"))
        if g.get("kmsKeyId"):
            rec.add_relationship("kms_key", g["kmsKeyId"])
        retention = g.get("retentionInDays")
        # R2: numeric log_retention_days so a QSA can filter for < 365 (10.5.1).
        rec.log_retention_days = str(retention) if retention else "never-expires"
        rec.backup_config = f"retention={retention} days" if retention else "retention=never expires"
        rec.logging_enabled = True
        rec.description_purpose = "CloudWatch Logs log group"
        if not retention:
            rec.add_note("no retention set (review 10.5.1: ≥12 months)")
        elif retention < 365:
            rec.add_note(f"retention {retention}d < 365d (review 10.5.1)")
        rec.public_exposed = False
        rec.source_calls = ["logs:DescribeLogGroups"]
        return rec


@register
class CloudWatchAlarmCollector(Collector):
    service = "cloudwatch"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("cloudwatch")
        alarms = ctx.call.paginate(client, "describe_alarms", account_id=ctx.account_id,
                                   region=ctx.region, service="cloudwatch", result_key="MetricAlarms")
        return collect_each(alarms, lambda a: self._build(ctx, a))

    def _build(self, ctx: CollectorContext, a: dict[str, Any]) -> ResourceRecord:
        name = a["AlarmName"]
        rec = new_record(ctx, service="cloudwatch", resource_type="cloudwatch:alarm",
                         resource_id=name, arn=a.get("AlarmArn", ""), name=name)
        rec.state_status = a.get("StateValue", "")
        rec.last_modified_activity = to_iso(a.get("AlarmConfigurationUpdatedTimestamp"))
        rec.description_purpose = a.get("AlarmDescription", "") or f"CloudWatch alarm on {a.get('MetricName','')}"
        rec.add_relationship("sns_actions", a.get("AlarmActions", []))
        rec.public_exposed = False
        rec.source_calls = ["cloudwatch:DescribeAlarms"]
        return rec


@register
class ConfigCollector(Collector):
    service = "config"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("config")
        out: list[ResourceRecord] = []

        recorders = ctx.call.call(client.describe_configuration_recorders, account_id=ctx.account_id,
                                  region=ctx.region, service="config",
                                  operation="DescribeConfigurationRecorders",
                                  default={"ConfigurationRecorders": []})
        statuses = ctx.call.call(client.describe_configuration_recorder_status, account_id=ctx.account_id,
                                 region=ctx.region, service="config",
                                 operation="DescribeConfigurationRecorderStatus",
                                 default={"ConfigurationRecordersStatus": []})
        status_by_name = {s.get("name"): s for s in statuses.get("ConfigurationRecordersStatus", [])}
        for r in recorders.get("ConfigurationRecorders", []):
            name = r.get("name", "")
            rec = new_record(ctx, service="config", resource_type="config:recorder",
                             resource_id=name, arn=synth_arn("config", ctx.region, ctx.account_id, f"config-recorder/{name}"),
                             name=name)
            st = status_by_name.get(name, {})
            rec.logging_enabled = bool(st.get("recording"))
            rec.state_status = st.get("lastStatus", "")
            grp = r.get("recordingGroup", {})
            rec.description_purpose = "AWS Config recorder"
            rec.notes = f"allSupported={grp.get('allSupported')} includeGlobal={grp.get('includeGlobalResourceTypes')}"
            rec.public_exposed = False
            rec.source_calls = ["config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus"]
            out.append(rec)

        rules = ctx.call.call(client.describe_config_rules, account_id=ctx.account_id, region=ctx.region,
                              service="config", operation="DescribeConfigRules",
                              default={"ConfigRules": []})
        for cr in rules.get("ConfigRules", []):
            rec = new_record(ctx, service="config", resource_type="config:rule",
                             resource_id=cr.get("ConfigRuleName", ""), arn=cr.get("ConfigRuleArn", ""),
                             name=cr.get("ConfigRuleName", ""))
            rec.state_status = cr.get("ConfigRuleState", "")
            rec.description_purpose = cr.get("Description", "") or "AWS Config rule"
            rec.public_exposed = False
            rec.source_calls = ["config:DescribeConfigRules"]
            out.append(rec)

        return out


@register
class EventBridgeCollector(Collector):
    service = "events"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("events")
        out: list[ResourceRecord] = []
        buses = ctx.call.call(client.list_event_buses, account_id=ctx.account_id, region=ctx.region,
                              service="events", operation="ListEventBuses", default={"EventBuses": []})
        for b in buses.get("EventBuses", []):
            rec = new_record(ctx, service="events", resource_type="events:event-bus",
                             resource_id=b.get("Name", ""), arn=b.get("Arn", ""), name=b.get("Name", ""))
            rec.description_purpose = "EventBridge event bus"
            if b.get("Policy"):
                rec.iam_policy_data["resource_based_policy"] = b["Policy"]
            rec.public_exposed = False
            rec.source_calls = ["events:ListEventBuses"]
            out.append(rec)

        rules = ctx.call.call(client.list_rules, account_id=ctx.account_id, region=ctx.region,
                              service="events", operation="ListRules", default={"Rules": []})
        for r in rules.get("Rules", []):
            rec = new_record(ctx, service="events", resource_type="events:rule",
                             resource_id=r.get("Name", ""), arn=r.get("Arn", ""), name=r.get("Name", ""))
            rec.state_status = r.get("State", "")
            rec.description_purpose = r.get("Description", "") or "EventBridge rule"
            rec.public_exposed = False
            rec.source_calls = ["events:ListRules"]
            out.append(rec)
        return out


def _ms(value: Any) -> Any:
    """Convert a CloudWatch epoch-millis timestamp into a datetime, else passthrough."""
    if isinstance(value, (int, float)):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
    return value
