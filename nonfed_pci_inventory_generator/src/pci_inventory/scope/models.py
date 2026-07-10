"""Scope-analysis data models: categories, confidence, classification, seeds, config.

These are the Stage-2 contract. A :class:`Classification` (category + basis +
confidence) is attached to every resource and serialized into the
``pci_scope`` / ``pci_scope_basis`` columns and the ``scope`` block of
``inventory-scoped.json``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Category(str, Enum):
    """The single scope category assigned to each resource."""

    CDE = "CDE"
    CONNECTED = "connected-to"
    SECURITY_IMPACTING = "security-impacting"
    OUT_OF_SCOPE = "out-of-scope"
    UNDETERMINED = "undetermined"


class Confidence(str, Enum):
    """How firmly the category is established."""

    DETERMINED = "DETERMINED"  # seed, proven reachability, or concrete IAM grant
    CANDIDATE = "CANDIDATE"  # heuristic signal only
    UNDETERMINED = "UNDETERMINED"  # insufficient data


# Category precedence when multiple signals apply (higher wins).
_CATEGORY_RANK = {
    Category.CDE: 5,
    Category.CONNECTED: 4,
    Category.SECURITY_IMPACTING: 3,
    Category.OUT_OF_SCOPE: 1,
    Category.UNDETERMINED: 0,
}
_CONFIDENCE_RANK = {Confidence.DETERMINED: 2, Confidence.CANDIDATE: 1, Confidence.UNDETERMINED: 0}


@dataclass
class Classification:
    """A scope verdict for one resource: category + basis + confidence.

    ``basis`` is a list of human-readable, structured reason strings (e.g.
    ``seed:tag(pci:cde=true)``, ``reachable-from-seed:path-0007``,
    ``iam-principal-with-cde-access:stmt#3``, ``heuristic:public-ip``). Multiple
    bases accumulate so the QSA sees every reason a resource was placed.
    """

    category: Category = Category.UNDETERMINED
    confidence: Confidence = Confidence.UNDETERMINED
    # A resource can legitimately be in scope for MORE THAN ONE reason — e.g. both
    # connected-to (network path) AND security-impacting (IAM access). PCI treats
    # these as distinct categories with different testing implications, so we keep
    # the full set rather than collapsing to one (re-audit C-2). ``category`` is the
    # highest-ranked PRIMARY for back-compat; ``categories`` carries all of them.
    categories: set[Category] = field(default_factory=set)
    basis: list[str] = field(default_factory=list)
    path_ids: list[str] = field(default_factory=list)  # reachability path ids supporting this
    notes: list[str] = field(default_factory=list)

    def add(self, category: Category, confidence: Confidence, basis: str) -> None:
        """Merge in a new signal: record the category, raise primary + confidence.

        Every in-scope category that applies is retained in ``categories``; the
        ``category`` field tracks the highest-ranked one as the primary label.
        Confidence is upgraded by rank. Every basis is retained.
        """
        if basis and basis not in self.basis:
            self.basis.append(basis)
        # undetermined/out-of-scope are not "extra reasons" to accumulate alongside
        # an in-scope category — only record the meaningful in-scope categories.
        if category not in (Category.UNDETERMINED,):
            self.categories.add(category)
        if _CATEGORY_RANK[category] > _CATEGORY_RANK[self.category]:
            self.category = category
        if _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[self.confidence]:
            self.confidence = confidence

    def secondary_categories(self) -> list[str]:
        """In-scope categories other than the primary (sorted, for output)."""
        return sorted(c.value for c in self.categories if c != self.category)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "categories": sorted(c.value for c in self.categories) or [self.category.value],
            "confidence": self.confidence.value,
            "basis": list(self.basis),
            "path_ids": list(self.path_ids),
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# Seeds + scope config
# --------------------------------------------------------------------------- #
class SeedKind(str, Enum):
    CDE_RESOURCE = "cde_resource"
    CDE_NETWORK = "cde_network"
    CONNECTED = "connected_declared"
    OUT_OF_SCOPE = "out_of_scope_declared"


@dataclass
class Seed:
    """A single human-declared seed and where it came from (for the basis)."""

    identifier: str  # ARN, resource id, vpc/subnet id, or CIDR
    kind: SeedKind
    source: str  # "config" | "tag(pci:cde=true)" | "flag" — precedence + audit trail


@dataclass
class ScopeConfig:
    """Resolved seed inputs for a scope run (from config file + tags + flags)."""

    cde_resources: list[str] = field(default_factory=list)
    cde_vpcs: list[str] = field(default_factory=list)
    cde_subnets: list[str] = field(default_factory=list)
    cde_cidrs: list[str] = field(default_factory=list)
    connected_declared: list[str] = field(default_factory=list)
    out_of_scope_declared: list[str] = field(default_factory=list)

    # Identifiers that originated from CLI flags (lowest precedence) — carried on
    # the config instance, not a module global, so runs/tests never share state.
    flag_ids: set[str] = field(default_factory=set)

    # Tag keys (case-insensitive) used to detect seeds from resource tags.
    cde_tag_keys: list[str] = field(default_factory=lambda: ["pci:cde", "pci-cde"])
    scope_tag_keys: list[str] = field(default_factory=lambda: ["pci:scope", "pci-scope"])
    data_class_tag_keys: list[str] = field(
        default_factory=lambda: ["data-classification", "dataclassification", "classification"]
    )

    @property
    def has_any_seed(self) -> bool:
        """True if any CDE seed was declared (resource or network)."""
        return bool(self.cde_resources or self.cde_vpcs or self.cde_subnets or self.cde_cidrs)
