"""Messaging / integration collectors (security-impacting): SNS topics, SQS
queues, Kinesis streams, Step Functions state machines, Amazon MQ brokers.

These can be security-impacting (resource policies allowing cross-account/public
access, unencrypted data). Resource policies are captured for the Stage 2 IAM
graph and analyzed (JSON-aware, not substring) for public exposure. All list
calls paginate so large accounts are never silently truncated.
"""

from __future__ import annotations


from pci_inventory.collectors.base import (
    Collector,
    CollectorContext,
    add_exposure,
    assess_resource_policy_exposure,
    new_record,
    register,
    set_not_exposed_if_unset,
    synth_arn,
    to_iso,
)
from pci_inventory.schema.models import ResourceRecord


@register
class SNSCollector(Collector):
    service = "sns"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("sns")
        topics = ctx.call.paginate(client, "list_topics", account_id=ctx.account_id,
                                   region=ctx.region, service="sns", result_key="Topics")
        out = []
        for t in topics:
            arn = t["TopicArn"]
            attrs = ctx.call.call(client.get_topic_attributes, account_id=ctx.account_id, region=ctx.region,
                                  service="sns", operation="GetTopicAttributes", resource_id=arn,
                                  default={"Attributes": {}}, TopicArn=arn)
            a = attrs.get("Attributes", {})
            rec = new_record(ctx, service="sns", resource_type="sns:topic",
                             resource_id=arn.split(":")[-1], arn=arn, name=arn.split(":")[-1])
            rec.description_purpose = a.get("DisplayName", "") or "SNS topic"
            rec.encryption_at_rest = bool(a.get("KmsMasterKeyId"))
            if a.get("KmsMasterKeyId"):
                rec.add_relationship("kms_key", a["KmsMasterKeyId"])
            assess_resource_policy_exposure(rec, a.get("Policy"), "sns")
            rec.state_status = f"subscriptions={a.get('SubscriptionsConfirmed','0')}"
            set_not_exposed_if_unset(rec)
            rec.source_calls = ["sns:ListTopics", "sns:GetTopicAttributes"]
            out.append(rec)
        return out


@register
class SQSCollector(Collector):
    service = "sqs"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("sqs")
        # list_queues paginates (NextToken); paginator avoids the 1000-queue cap.
        urls = ctx.call.paginate(client, "list_queues", account_id=ctx.account_id,
                                 region=ctx.region, service="sqs", result_key="QueueUrls")
        out = []
        for url in urls:
            attrs = ctx.call.call(client.get_queue_attributes, account_id=ctx.account_id, region=ctx.region,
                                  service="sqs", operation="GetQueueAttributes", resource_id=url,
                                  default={"Attributes": {}}, QueueUrl=url, AttributeNames=["All"])
            a = attrs.get("Attributes", {})
            name = url.rstrip("/").split("/")[-1]
            arn = a.get("QueueArn", synth_arn("sqs", ctx.region, ctx.account_id, name))
            rec = new_record(ctx, service="sqs", resource_type="sqs:queue",
                             resource_id=name, arn=arn, name=name)
            rec.description_purpose = "SQS queue"
            kms = a.get("KmsMasterKeyId")
            sse_managed = a.get("SqsManagedSseEnabled") == "true"
            rec.encryption_at_rest = bool(kms or sse_managed)
            rec.encryption_at_rest_detail = "kms" if kms else ("sqs-managed-sse" if sse_managed else "")
            if kms:
                rec.add_relationship("kms_key", kms)
            rec.dns_names = [url]
            assess_resource_policy_exposure(rec, a.get("Policy"), "sqs")
            set_not_exposed_if_unset(rec)
            rec.source_calls = ["sqs:ListQueues", "sqs:GetQueueAttributes"]
            out.append(rec)
        return out


@register
class KinesisCollector(Collector):
    service = "kinesis"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("kinesis")
        # list_streams paginates (HasMoreStreams); paginator avoids the 100-stream cap.
        names = ctx.call.paginate(client, "list_streams", account_id=ctx.account_id,
                                  region=ctx.region, service="kinesis", result_key="StreamNames")
        out = []
        for name in names:
            summary = ctx.call.call(client.describe_stream_summary, account_id=ctx.account_id, region=ctx.region,
                                    service="kinesis", operation="DescribeStreamSummary", resource_id=name,
                                    default=None, StreamName=name)
            d = (summary or {}).get("StreamDescriptionSummary", {})
            rec = new_record(ctx, service="kinesis", resource_type="kinesis:stream",
                             resource_id=name, arn=d.get("StreamARN", ""), name=name)
            rec.state_status = d.get("StreamStatus", "")
            rec.creation_date = to_iso(d.get("StreamCreationTimestamp"))
            rec.encryption_at_rest = d.get("EncryptionType", "NONE") != "NONE"
            if d.get("KeyId"):
                rec.add_relationship("kms_key", d["KeyId"])
            if d.get("RetentionPeriodHours"):
                rec.backup_config = f"retention={d['RetentionPeriodHours']}h"
            rec.description_purpose = "Kinesis data stream"
            rec.public_exposed = False
            rec.source_calls = ["kinesis:ListStreams", "kinesis:DescribeStreamSummary"]
            out.append(rec)
        return out


@register
class StepFunctionsCollector(Collector):
    service = "states"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("stepfunctions")
        machines = ctx.call.paginate(client, "list_state_machines", account_id=ctx.account_id,
                                     region=ctx.region, service="states", result_key="stateMachines")
        out = []
        for m in machines:
            arn = m.get("stateMachineArn", "")
            rec = new_record(ctx, service="states", resource_type="states:state-machine",
                             resource_id=m.get("name", ""), arn=arn, name=m.get("name", ""))
            rec.creation_date = to_iso(m.get("creationDate"))
            rec.is_bespoke_software = True
            rec.description_purpose = f"Step Functions state machine ({m.get('type','')})"
            # R3: logging/tracing config + execution role for Stage 2.
            desc = ctx.call.call(client.describe_state_machine, account_id=ctx.account_id, region=ctx.region,
                                 service="states", operation="DescribeStateMachine", resource_id=arn,
                                 default=None, stateMachineArn=arn)
            if desc:
                log_cfg = desc.get("loggingConfiguration", {})
                level = log_cfg.get("level", "OFF")
                rec.logging_enabled = level != "OFF"
                rec.logging_detail = f"level={level}"
                rec.add_relationship("execution_role", desc.get("roleArn"))
                rec.iam_policy_data["execution_role"] = desc.get("roleArn")
                if desc.get("tracingConfiguration", {}).get("enabled"):
                    rec.add_note("X-Ray tracing enabled")
            rec.public_exposed = False
            rec.source_calls = ["stepfunctions:ListStateMachines", "stepfunctions:DescribeStateMachine"]
            out.append(rec)
        return out


@register
class MQCollector(Collector):
    service = "mq"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("mq")
        # list_brokers paginates (NextToken).
        brokers = ctx.call.paginate(client, "list_brokers", account_id=ctx.account_id,
                                    region=ctx.region, service="mq", result_key="BrokerSummaries")
        out = []
        for b in brokers:
            bid = b.get("BrokerId", "")
            rec = new_record(ctx, service="mq", resource_type="mq:broker",
                             resource_id=bid, arn=b.get("BrokerArn", ""),
                             name=b.get("BrokerName", ""))
            rec.state_status = b.get("BrokerState", "")
            rec.creation_date = to_iso(b.get("Created"))
            rec.os_platform_engine = b.get("EngineType", "")
            rec.description_purpose = "Amazon MQ broker"
            if b.get("DeploymentMode"):
                rec.state_status = f"{b.get('BrokerState','')} ({b.get('DeploymentMode')})"
            # R3: DescribeBroker for public accessibility + encryption + SGs.
            desc = ctx.call.call(client.describe_broker, account_id=ctx.account_id, region=ctx.region,
                                 service="mq", operation="DescribeBroker", resource_id=bid,
                                 default=None, BrokerId=bid)
            if desc:
                rec.os_platform_version = desc.get("EngineVersion", "")
                enc = desc.get("EncryptionOptions", {})
                rec.encryption_at_rest = bool(enc) if enc else None
                if enc.get("KmsKeyId"):
                    rec.add_relationship("kms_key", enc["KmsKeyId"])
                rec.add_relationship("security_groups", desc.get("SecurityGroups", []))
                rec.add_relationship("subnets", desc.get("SubnetIds", []))
                if desc.get("PubliclyAccessible"):
                    add_exposure(rec, "mq-publicly-accessible")
                rec.encryption_in_transit = True  # MQ enforces TLS on broker endpoints
            set_not_exposed_if_unset(rec)
            rec.source_calls = ["mq:ListBrokers", "mq:DescribeBroker"]
            out.append(rec)
        return out
