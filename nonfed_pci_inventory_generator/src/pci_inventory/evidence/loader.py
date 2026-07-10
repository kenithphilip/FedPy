"""Load the Stage 2 scoped artifact (or fall back to the Stage 1 inventory).

Reuses the Stage 2 :class:`InventoryIndex` for indexing. If the scoped artifact is
absent, falls back to ``output/inventory.json`` and flags ``scope_missing`` so the
caller can emit a loud banner and treat every resource's scope as UNDETERMINED.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from pci_inventory.scope.artifact import InventoryIndex, load_inventory

logger = logging.getLogger("pci_inventory.evidence.loader")


@dataclass
class LoadedArtifact:
    index: InventoryIndex
    scope_missing: bool  # True when we fell back to Stage 1 (no scope context)
    source_path: Path


def load_for_evidence(scoped_path: str | Path = "output/inventory-scoped.json",
                      inventory_path: str | Path = "output/inventory.json") -> LoadedArtifact:
    """Load the scoped artifact, falling back to the Stage 1 inventory with a warning."""
    sp = Path(scoped_path)
    if sp.exists():
        index = load_inventory(sp, expect_scoped=True)  # validates + indexes either shape
        if "scope_analysis" not in index.document and "scope_schema_version" not in index.document:
            logger.warning("%s lacks scope analysis — treating as unscoped.", sp)
            return LoadedArtifact(index, scope_missing=True, source_path=sp)
        logger.info("Loaded Stage 2 scoped artifact: %s", sp)
        return LoadedArtifact(index, scope_missing=False, source_path=sp)

    ip = Path(inventory_path)
    if ip.exists():
        logger.warning(
            "SCOPE CONTEXT MISSING: %s not found; falling back to the Stage 1 inventory %s. "
            "Evidence will be produced WITHOUT scope classification — run Stage 2 "
            "(pci-inventory scope) first for scope-prioritized evidence.", sp, ip)
        return LoadedArtifact(load_inventory(ip), scope_missing=True, source_path=ip)

    raise FileNotFoundError(
        f"Neither {sp} nor {ip} found. Run Stage 1 (pci-inventory) and ideally Stage 2 "
        f"(pci-inventory scope) before the evidence stage.")


def resource_scope(resource: dict) -> tuple[str, str]:
    """Return (scope_category, scope_confidence) for a resource record.

    Prefers the Stage 2 ``scope`` block; falls back to the ``pci_scope`` column;
    defaults to UNDETERMINED when scope context is absent.
    """
    scope = resource.get("scope")
    if isinstance(scope, dict) and scope.get("category"):
        return scope.get("category", "undetermined"), scope.get("confidence", "UNDETERMINED")
    pci_scope = resource.get("pci_scope", "")
    if pci_scope and "pending" not in pci_scope.lower() and "undetermined" not in pci_scope.lower():
        return pci_scope, "UNKNOWN"
    return "undetermined", "UNDETERMINED"
