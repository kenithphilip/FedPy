"""Stage 3 — evidence & control-relevance enrichment.

Reads the Stage 2 ``output/inventory-scoped.json`` (falls back to Stage 1
``output/inventory.json`` with a loud scope-missing warning), maps the inventory's
already-collected configuration evidence to all 12 PCI DSS v4.0.1 requirements,
runs a bounded set of read-only follow-up *findings* queries, computes derived
indicators, and writes the final consolidated QSA workbook + CSV +
``output/inventory-evidence.json``.

Augments prior records; never drops or alters Stage 1/2 data. Read-only. Derived
indicators are tool aids — NOT compliance determinations.
"""

from pci_inventory.evidence.models import (
    EvidenceRow,
    EvidenceThresholds,
    RequirementDomain,
)

__all__ = ["EvidenceRow", "EvidenceThresholds", "RequirementDomain"]
