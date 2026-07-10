"""Seed loading + resolution.

Three sources, precedence **explicit config > tags > CLI flags** (see
``docs/scope-seed-and-tagging-convention.md``). The loader produces a
:class:`ScopeConfig` (the declared inputs) and, given the loaded resources, a
``SeedResolver`` that maps each resource to its declared :class:`Seed` (if any),
recording the source for the classification basis.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from pci_inventory.scope.models import ScopeConfig, Seed, SeedKind
from pci_inventory.utils import first_tag

logger = logging.getLogger("pci_inventory.scope.seeds")


def load_scope_config(
    path: str | Path | None,
    *,
    seed_arns: list[str] | None = None,
    seed_vpcs: list[str] | None = None,
    seed_subnets: list[str] | None = None,
    seed_cidrs: list[str] | None = None,
    out_of_scope: list[str] | None = None,
) -> ScopeConfig:
    """Build a ScopeConfig from an optional seeds file plus CLI-flag additions.

    Config-file entries and CLI flags are unioned into the ScopeConfig; per-source
    precedence is applied later, per resource, in :class:`SeedResolver`.
    """
    cfg = ScopeConfig()

    if path is not None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Seeds file not found: {p}")
        text = p.read_text(encoding="utf-8")
        data: dict[str, Any]
        if p.suffix.lower() in (".yaml", ".yml"):
            data = yaml.safe_load(text) or {}
        elif p.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            try:
                data = yaml.safe_load(text) or {}
            except yaml.YAMLError:
                data = json.loads(text)
        # A YAML key that is present but empty (e.g. `cde_resources:` with all
        # entries commented out) parses to None, so coerce None -> [] / {} before
        # iterating — otherwise list(None) raises and a half-filled template fails.
        def _list(key: str, src: dict[str, Any] | None = None) -> list[Any]:
            return list((src if src is not None else data).get(key) or [])

        cfg.cde_resources = _list("cde_resources")
        networks = data.get("cde_networks") or {}
        cfg.cde_vpcs = _list("vpcs", networks)
        cfg.cde_subnets = _list("subnets", networks)
        cfg.cde_cidrs = _list("cidrs", networks)
        cfg.connected_declared = _list("connected_declared")
        cfg.out_of_scope_declared = _list("out_of_scope_declared")
        # Optional tag-key overrides.
        for fld, key in [("cde_tag_keys", "cde_tag_keys"),
                         ("scope_tag_keys", "scope_tag_keys"),
                         ("data_class_tag_keys", "data_class_tag_keys")]:
            if data.get(key):
                setattr(cfg, fld, list(data[key]))

    # CLI-flag additions (lowest precedence, but unioned in).
    cfg.cde_resources += list(seed_arns or [])
    cfg.cde_vpcs += list(seed_vpcs or [])
    cfg.cde_subnets += list(seed_subnets or [])
    cfg.cde_cidrs += list(seed_cidrs or [])
    cfg.out_of_scope_declared += list(out_of_scope or [])

    # Track which identifiers came only from flags (for precedence/source labels).
    cfg.flag_ids = (set(seed_arns or []) | set(seed_vpcs or []) | set(seed_subnets or [])
                    | set(seed_cidrs or []) | set(out_of_scope or []))
    return cfg


def _matches(resource: dict[str, Any], identifier: str) -> bool:
    """True if a resource matches a seed identifier (ARN, native id, or name)."""
    if not identifier:
        return False
    return identifier in (resource.get("arn"), resource.get("resource_id"), resource.get("name"))


class SeedResolver:
    """Resolves the declared seed status of resources, honoring precedence.

    Precedence per resource: explicit config > tags > CLI flags. The first source
    that declares the resource wins; conflicts are surfaced in ``conflicts``.
    """

    def __init__(self, cfg: ScopeConfig, resources: list[dict[str, Any]]):
        self.cfg = cfg
        self.resources = resources
        self.conflicts: list[str] = []
        # arn -> Seed (the winning declaration).
        self._by_arn: dict[str, Seed] = {}
        self._resolve()

    # -- config / flag membership helpers --------------------------------- #
    def _config_kind(self, r: dict[str, Any]) -> tuple[SeedKind | None, str]:
        """Return (kind, source) if the resource is declared in explicit config/flags."""
        ident_hit = lambda lst: any(_matches(r, i) for i in lst)  # noqa: E731
        # Network membership for the resource's own ids.
        flag_ids = self.cfg.flag_ids
        if ident_hit(self.cfg.cde_resources):
            ids = {r.get("arn"), r.get("resource_id"), r.get("name")}
            from_flag = bool(ids & flag_ids)
            return SeedKind.CDE_RESOURCE, ("flag" if from_flag else "config")
        if r.get("resource_id") in self.cfg.cde_vpcs or r.get("resource_id") in self.cfg.cde_subnets:
            from_flag = r.get("resource_id") in flag_ids
            return SeedKind.CDE_NETWORK, ("flag" if from_flag else "config")
        if ident_hit(self.cfg.connected_declared):
            return SeedKind.CONNECTED, "config"
        if ident_hit(self.cfg.out_of_scope_declared):
            from_flag = bool({r.get("arn"), r.get("resource_id")} & flag_ids)
            return SeedKind.OUT_OF_SCOPE, ("flag" if from_flag else "config")
        return None, ""

    def _tag_kind(self, r: dict[str, Any]) -> tuple[SeedKind | None, str]:
        """Return (kind, source) if the resource's tags declare a seed."""
        tags = r.get("tags", {}) or {}
        cde = first_tag(tags, self.cfg.cde_tag_keys)
        if cde.lower() == "true":
            return SeedKind.CDE_RESOURCE, "tag(pci:cde=true)"
        scope = first_tag(tags, self.cfg.scope_tag_keys).lower()
        if scope == "cde":
            return SeedKind.CDE_RESOURCE, "tag(pci:scope=cde)"
        if scope == "connected":
            return SeedKind.CONNECTED, "tag(pci:scope=connected)"
        if scope == "out":
            return SeedKind.OUT_OF_SCOPE, "tag(pci:scope=out)"
        data_class = first_tag(tags, self.cfg.data_class_tag_keys).lower()
        if data_class in ("chd", "sad"):
            return SeedKind.CDE_RESOURCE, f"tag(data-classification={data_class})"
        return None, ""

    def _resolve(self) -> None:
        for r in self.resources:
            arn = r.get("arn", "")
            config_kind, config_src = self._config_kind(r)
            tag_kind, tag_src = self._tag_kind(r)
            # Precedence: config > tag (flags are folded into config_kind above).
            if config_kind is not None:
                self._by_arn[arn] = Seed(arn, config_kind, config_src)
                if tag_kind is not None and tag_kind != config_kind:
                    self.conflicts.append(
                        f"{arn}: config says {config_kind.value} ({config_src}) but "
                        f"tag says {tag_kind.value} ({tag_src}) — config wins")
            elif tag_kind is not None:
                self._by_arn[arn] = Seed(arn, tag_kind, tag_src)

    # -- public API -------------------------------------------------------- #
    def seed_for(self, arn: str) -> Seed | None:
        return self._by_arn.get(arn)

    @property
    def cde_arns(self) -> set[str]:
        return {a for a, s in self._by_arn.items() if s.kind == SeedKind.CDE_RESOURCE}

    @property
    def connected_arns(self) -> set[str]:
        return {a for a, s in self._by_arn.items() if s.kind == SeedKind.CONNECTED}

    @property
    def out_of_scope_arns(self) -> set[str]:
        return {a for a, s in self._by_arn.items() if s.kind == SeedKind.OUT_OF_SCOPE}

    @property
    def has_any_cde_seed(self) -> bool:
        """True if any CDE seed (resource or declared network) exists."""
        return bool(self.cde_arns) or self.cfg.has_any_seed
