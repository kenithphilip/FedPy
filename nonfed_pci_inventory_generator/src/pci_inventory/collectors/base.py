"""Collector base class, registry, and shared record-building helpers.

A :class:`Collector` knows its service namespace and whether it is regional or
global. The orchestrator calls :meth:`Collector.collect` once per included region
(for regional collectors) or once per account (for global collectors).

Helpers here centralize the common normalization work — tag derivation,
exposure/encryption defaults, ARN synthesis — so individual collectors stay
small and consistent with the column contract.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from pci_inventory import __version__
from pci_inventory.auth import AccountSession
from pci_inventory.concurrency import CallContext
from pci_inventory.config import AppConfig
from pci_inventory.schema.models import ResourceRecord
from pci_inventory.utils import GLOBAL_REGION, Sentinel, first_tag, iso_utc

logger = logging.getLogger("pci_inventory.collectors")


@dataclass
class CollectorContext:
    """Everything a collector needs for one (account, region) invocation."""

    session: AccountSession
    region: str
    call: CallContext
    config: AppConfig

    @property
    def account_id(self) -> str:
        return self.session.account_id

    @property
    def account_alias(self) -> str:
        return self.session.alias

    def client(self, service: str, region: str | None = None) -> Any:
        """Thread-local client for ``service`` (defaults to this context's region)."""
        return self.session.client(service, region=region if region is not None else self.region)


class Collector:
    """Base class for all service collectors.

    Subclasses set :attr:`service`, :attr:`is_global`, and implement
    :meth:`collect`. They build records with :func:`new_record` and the helper
    methods, returning a list of :class:`ResourceRecord`.
    """

    service: str = "unknown"
    is_global: bool = False
    # Some "global" services must be called against a specific home region.
    global_home_region: str | None = None

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:  # pragma: no cover - interface
        raise NotImplementedError

    # -- shared helpers ----------------------------------------------------- #
    def _finalize(self, ctx: CollectorContext, record: ResourceRecord) -> ResourceRecord:
        """Apply common derivations every record needs before emission."""
        record.collector_version = __version__
        record.account_alias = ctx.account_alias or record.account_alias
        apply_tag_derivations(record, ctx.config)
        derive_segmentation_role(record)
        return record


# Resource types that act as network segmentation / NSC controls (Req 1.x, 11.4.5).
_NSC_RESOURCE_TYPES = frozenset({
    "ec2:security-group", "ec2:network-acl", "ec2:route-table",
    "ec2:internet-gateway", "ec2:nat-gateway", "ec2:vpc-peering",
    "ec2:transit-gateway", "ec2:tgw-attachment", "ec2:vpc-endpoint",
    "ec2:vpn-connection", "ec2:client-vpn-endpoint", "directconnect:connection",
    "networkfirewall:firewall", "networkfirewall:firewall-policy",
    "fms:policy", "wafv2:web-acl-regional", "wafv2:web-acl-cloudfront",
})


def derive_segmentation_role(record: ResourceRecord) -> None:
    """Mark whether a component is a network segmentation/NSC control."""
    record.segmentation_role = "nsc" if record.resource_type in _NSC_RESOURCE_TYPES else "none"


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
REGISTRY: list[Collector] = []


def register(collector_cls: type[Collector]) -> type[Collector]:
    """Class decorator: instantiate and register a collector."""
    REGISTRY.append(collector_cls())
    return collector_cls


# --------------------------------------------------------------------------- #
# Record construction helpers
# --------------------------------------------------------------------------- #
def new_record(
    ctx: CollectorContext,
    *,
    service: str,
    resource_type: str,
    resource_id: str,
    arn: str,
    region: str | None = None,
    name: str = "",
) -> ResourceRecord:
    """Create a record pre-populated with identity fields for this context."""
    return ResourceRecord(
        arn=arn,
        resource_id=resource_id,
        account_id=ctx.account_id,
        region=region if region is not None else ctx.region,
        service=service,
        resource_type=resource_type,
        account_alias=ctx.account_alias,
        name=name,
    )


def synth_arn(service: str, region: str, account_id: str, resource_path: str) -> str:
    """Synthesize an ARN for services/resources without a native one."""
    reg = "" if region == GLOBAL_REGION else region
    return f"arn:aws:{service}:{reg}:{account_id}:{resource_path}"


def apply_tag_derivations(record: ResourceRecord, config: AppConfig) -> None:
    """Derive environment/owner/data-classification/tag-completeness from tags.

    Also captures any PCI scope tags into ``iam_policy_data['scope_tags']`` so
    Stage 2 can use them without re-reading tags. (We keep ``pci_scope`` itself as
    the Stage-1 placeholder.)
    """
    tags = record.tags or {}

    if not record.environment:
        record.environment = first_tag(tags, config.env_tag_keys)
    if not record.owner_team:
        record.owner_team = first_tag(tags, config.owner_tag_keys)

    data_class = first_tag(tags, config.data_class_tag_keys)
    if data_class:
        record.data_classification = data_class

    # Capture scope tags as a Stage-2 signal (does not set pci_scope).
    scope_tag_values = {
        k: tags[k]
        for k in tags
        if any(k.lower() == s.lower() for s in config.scope_tag_keys)
    }
    if scope_tag_values:
        record.iam_policy_data.setdefault("scope_tags", scope_tag_values)

    # Tag completeness against the configured required set.
    required = config.required_tags
    if required:
        lowered = {k.lower() for k in tags}
        present = [t for t in required if t.lower() in lowered]
        missing = [t for t in required if t.lower() not in lowered]
        suffix = f" (missing: {', '.join(missing)})" if missing else ""
        record.tag_completeness = f"{len(present)}/{len(required)}{suffix}"

    if not record.name:
        record.name = first_tag(tags, ["Name"])


def add_exposure(record: ResourceRecord, reason: str) -> None:
    """Mark a record as publicly exposed and append the concrete reason."""
    record.public_exposed = True
    if reason and reason not in record.exposure_basis:
        record.exposure_basis.append(reason)


def set_not_exposed_if_unset(record: ResourceRecord) -> None:
    """Default ``public_exposed`` to False when a collector found no exposure."""
    if record.public_exposed is None:
        record.public_exposed = False


def assess_resource_policy_exposure(record: ResourceRecord, policy: Any, label: str) -> None:
    """Record a resource-based policy on a record and flag public exposure correctly.

    Uses :func:`pci_inventory.utils.analyze_resource_policy` (JSON-aware) instead
    of fragile substring matching, so it handles ``{"AWS": ["*"]}`` list form and
    distinguishes a wildcard principal that is scoped by a ``Condition``
    (recorded as ``<label>-public-conditioned`` + a note) from a bare public
    grant (``<label>-public``). External (non-wildcard) principals are noted for
    the Stage 2 IAM graph.
    """
    from pci_inventory.utils import analyze_resource_policy

    if not policy:
        return
    record.iam_policy_data["resource_based_policy"] = policy
    analysis = analyze_resource_policy(policy)
    if analysis["parse_error"]:
        record.add_note(f"{label} policy: could not parse for public-access check")
        return
    if analysis["public"]:
        if analysis["conditioned"]:
            add_exposure(record, f"{label}-public-conditioned")
            record.add_note(f"{label}: wildcard principal scoped by Condition — verify in Stage 2")
        else:
            add_exposure(record, f"{label}-public")
    if analysis["external_principals"]:
        record.iam_policy_data.setdefault("external_principals", analysis["external_principals"])


def to_iso(value: Any) -> str:
    """Render a boto3 datetime (or None) as ISO 8601 UTC."""
    if value is None:
        return ""
    try:
        return iso_utc(value)
    except Exception:  # noqa: BLE001
        return str(value)


def collect_each(
    items: Iterable[Any],
    builder: Callable[[Any], ResourceRecord | None],
) -> list[ResourceRecord]:
    """Map a builder over items, skipping Nones and isolating per-item errors."""
    out: list[ResourceRecord] = []
    for item in items:
        try:
            rec = builder(item)
        except Exception as exc:  # noqa: BLE001 - one bad item must not abort
            logger.debug("Record builder error: %s", exc)
            continue
        if rec is not None:
            out.append(rec)
    return out


# Re-export for convenience in collector modules.
__all__ = [
    "Collector",
    "CollectorContext",
    "REGISTRY",
    "register",
    "new_record",
    "synth_arn",
    "add_exposure",
    "set_not_exposed_if_unset",
    "assess_resource_policy_exposure",
    "to_iso",
    "collect_each",
    "Sentinel",
]
