"""Service collectors.

Each domain module registers one or more :class:`~pci_inventory.collectors.base.Collector`
subclasses via the :data:`REGISTRY`. The orchestrator iterates the registry to
build work units per account/region.
"""

from pci_inventory.collectors.base import REGISTRY, Collector, CollectorContext

# Importing the domain modules registers their collectors as a side effect.
from pci_inventory.collectors import (  # noqa: E402,F401
    compute,
    network,
    edge,
    storage,
    database,
    iam,
    security,
    logging_mon,
    management,
    messaging,
    extra,
)

__all__ = ["REGISTRY", "Collector", "CollectorContext"]
