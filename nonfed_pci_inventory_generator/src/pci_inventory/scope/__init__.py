"""Stage 2 — scope analysis.

Reads the Stage 1 ``output/inventory.json`` artifact, expands from human-declared
seeds via a reachability graph (route ∧ SG ∧ NACL) and an IAM graph, validates
segmentation, and writes ``output/inventory-scoped.json`` for Stage 3.

The tool does NOT originate scope: scope comes from seeds (config > tags > flags).
Without seeds it flags candidates only and never asserts in-scope. Isolation
evidence proves isolation, not the absence of cardholder data.
"""

from pci_inventory.scope.models import (
    Category,
    Classification,
    Confidence,
    ScopeConfig,
    Seed,
)

__all__ = ["Category", "Classification", "Confidence", "ScopeConfig", "Seed"]
