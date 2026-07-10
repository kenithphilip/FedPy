"""Loader + index for the Stage 1 ``inventory.json`` artifact.

Stage 2 reads (never re-collects) the Stage 1 document and indexes resources by
ARN, native id, type, and the relationship keys the graph needs. The
:class:`InventoryIndex` is the single in-memory view all graph layers build on.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger("pci_inventory.scope.artifact")


class InventoryIndex:
    """Indexed, read-only view of the Stage 1 inventory document."""

    def __init__(self, document: dict[str, Any]):
        self.document = document
        self.resources: list[dict[str, Any]] = document.get("resources", [])
        # Primary indexes. ARN is the unique key. Native ids (sg-…, subnet-…) are
        # unique only within an (account, region) — they REPEAT across regions, so
        # a plain id→resource map would silently return the wrong-region resource
        # (re-audit S1c). We therefore keep a multimap and only resolve a bare id
        # when it is globally unambiguous; ambiguous ids are logged and return None.
        self.by_arn: dict[str, dict[str, Any]] = {}
        self.by_id_all: dict[str, list[dict[str, Any]]] = {}
        self.by_type: dict[str, list[dict[str, Any]]] = {}
        for r in self.resources:
            if r.get("arn"):
                self.by_arn[r["arn"]] = r
            if r.get("resource_id"):
                self.by_id_all.setdefault(r["resource_id"], []).append(r)
            self.by_type.setdefault(r.get("resource_type", ""), []).append(r)

    # -- accessors --------------------------------------------------------- #
    def get(self, identifier: str) -> dict[str, Any] | None:
        """Resolve a resource by ARN (preferred) or unambiguous native id.

        ARN lookup is exact. A bare native id resolves only when it maps to a
        single resource across the whole artifact; if it is ambiguous (same id in
        multiple regions/accounts) this logs a warning and returns None rather
        than guessing the wrong region.
        """
        hit = self.by_arn.get(identifier)
        if hit is not None:
            return hit
        candidates = self.by_id_all.get(identifier, [])
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            logger.warning(
                "Ambiguous native id %r matches %d resources across regions/accounts; "
                "use the full ARN to disambiguate.", identifier, len(candidates))
        return None

    def get_all(self, identifier: str) -> list[dict[str, Any]]:
        """All resources matching an ARN or native id (across regions/accounts)."""
        if identifier in self.by_arn:
            return [self.by_arn[identifier]]
        return list(self.by_id_all.get(identifier, []))

    def of_type(self, *resource_types: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for t in resource_types:
            out.extend(self.by_type.get(t, []))
        return out

    def accounts(self) -> list[dict[str, Any]]:
        return self.document.get("accounts_scanned", [])

    def regions_in_use(self) -> set[tuple[str, str]]:
        """(account_id, region) pairs that were included in Stage 1 collection."""
        out: set[tuple[str, str]] = set()
        for c in self.document.get("regions_coverage", []):
            if c.get("status") == "included" and c.get("region") not in (None, "GLOBAL"):
                out.add((c.get("account_id", ""), c.get("region", "")))
        return out

    @staticmethod
    def relationship(resource: dict[str, Any], key: str) -> list[str]:
        """Return a relationship list for a resource (always a list of strings)."""
        rel = (resource.get("relationships") or {}).get(key)
        if rel is None:
            return []
        if isinstance(rel, list):
            return [str(x) for x in rel if x not in (None, "")]
        return [str(rel)] if rel not in (None, "") else []

    def iter_by_types(self, types: Iterable[str]):
        for t in types:
            yield from self.by_type.get(t, [])


def load_inventory(path: str | Path, expect_scoped: bool = False) -> InventoryIndex:
    """Load and index the Stage 1 inventory.json artifact (with validation).

    ``expect_scoped=True`` (Stage 3) suppresses the "already scoped" warning, since
    consuming a scoped artifact is the intended input there.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Stage 1 artifact not found: {p}. Run the Stage 1 inventory first "
            f"(pci-inventory) to produce output/inventory.json.")
    try:
        document = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{p} is not valid JSON ({exc}). Expected a Stage 1 inventory.json.") from exc
    if not isinstance(document, dict) or "resources" not in document:
        raise ValueError(
            f"{p} does not look like a Stage 1 inventory.json (no 'resources' key).")
    sv = str(document.get("schema_version", "?"))
    n = len(document.get("resources", []))
    # Warn (don't fail) on schema surprises so the operator isn't blindsided.
    if sv.split(".", 1)[0] not in ("1", "?"):
        logger.warning("inventory.json schema_version=%s — expected 1.x; proceeding best-effort.", sv)
    if not expect_scoped and ("scope_schema_version" in document or "scope_analysis" in document):
        logger.warning("Input already contains scope analysis (scope_schema_version present); "
                       "re-running scope on a scoped artifact. Point --inventory at the Stage 1 file.")
    if n == 0:
        logger.warning("inventory.json contains zero resources — scope analysis will be empty.")
    logger.info("Loaded inventory.json schema=%s with %d resources", sv, n)
    return InventoryIndex(document)
