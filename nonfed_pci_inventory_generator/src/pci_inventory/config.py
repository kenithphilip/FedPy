"""Configuration model and loader.

The tool runs with zero configuration by default (single account, ambient
credentials). An optional YAML/JSON config file extends it to multiple accounts
and/or AWS Organizations discovery. The config is architected so a single
org config trivially generalizes to a list of orgs later (``organizations``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Default cross-account role name for the (optional) assume-role seam. The user's
# default path uses ambient SSO credentials and does NOT assume a role.
DEFAULT_AUDIT_ROLE_NAME = "PCIInventoryAuditRole"

# Tag keys consulted (case-insensitive) for derived columns.
DEFAULT_ENV_TAG_KEYS = ["environment", "env", "stage"]
DEFAULT_OWNER_TAG_KEYS = ["owner", "team", "cost-center", "costcenter"]
DEFAULT_DATA_CLASS_TAG_KEYS = ["data-classification", "dataclassification", "classification"]
DEFAULT_SCOPE_TAG_KEYS = ["pci:scope", "pci-scope", "pci:cde", "pci-cde"]
# Governance tags whose presence is scored for tag_completeness.
DEFAULT_REQUIRED_TAGS = ["Name", "environment", "owner", "data-classification"]


@dataclass
class AccountTarget:
    """One target account for the multi-account seam.

    ``profile`` uses a named AWS profile (e.g. an SSO profile). ``role_arn`` /
    ``role_name`` use STS AssumeRole from the current session. If neither is set,
    ambient credentials are used (single-account default).
    """

    account_id: str | None = None
    alias: str | None = None
    profile: str | None = None
    role_arn: str | None = None
    role_name: str | None = None
    external_id: str | None = None


@dataclass
class OrgTarget:
    """An AWS Organizations discovery target (management/delegated-admin)."""

    profile: str | None = None
    role_name: str = DEFAULT_AUDIT_ROLE_NAME  # role to assume in member accounts
    external_id: str | None = None
    exclude_account_ids: list[str] = field(default_factory=list)


@dataclass
class ConcurrencyConfig:
    """Parallelism and rate-limit tuning (safe defaults)."""

    max_workers: int = 12  # global bounded thread pool size
    retries_max_attempts: int = 10  # boto3 adaptive retry attempts
    # Per-service-class concurrency caps (hard-throttling services get 1-2).
    hard_throttle_cap: int = 2
    medium_throttle_cap: int = 6
    # Services treated as hard-throttling (see research/03 throttle classes).
    hard_throttle_services: list[str] = field(
        default_factory=lambda: ["iam", "organizations", "config", "apigateway", "apigatewayv2", "cloudtrail"]
    )
    # Global token-bucket: sustained calls/sec and burst capacity.
    tokens_per_second: float = 40.0
    bucket_capacity: float = 80.0


@dataclass
class AppConfig:
    """Top-level application configuration."""

    accounts: list[AccountTarget] = field(default_factory=list)
    organizations: list[OrgTarget] = field(default_factory=list)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)

    # Region controls (mirrored by CLI flags, which take precedence).
    regions: list[str] = field(default_factory=list)  # allowlist
    exclude_regions: list[str] = field(default_factory=list)
    all_regions: bool = False  # force full collection incl. empty regions
    include_empty_regions: bool = False  # record + collect empty regions

    # Tag-derivation keys.
    env_tag_keys: list[str] = field(default_factory=lambda: list(DEFAULT_ENV_TAG_KEYS))
    owner_tag_keys: list[str] = field(default_factory=lambda: list(DEFAULT_OWNER_TAG_KEYS))
    data_class_tag_keys: list[str] = field(default_factory=lambda: list(DEFAULT_DATA_CLASS_TAG_KEYS))
    scope_tag_keys: list[str] = field(default_factory=lambda: list(DEFAULT_SCOPE_TAG_KEYS))
    required_tags: list[str] = field(default_factory=lambda: list(DEFAULT_REQUIRED_TAGS))

    output_dir: str = "output"

    @property
    def is_single_account_default(self) -> bool:
        """True when no multi-account/org config was supplied (ambient creds)."""
        return not self.accounts and not self.organizations


def _coerce_accounts(raw: list[dict[str, Any]] | None) -> list[AccountTarget]:
    out: list[AccountTarget] = []
    for a in raw or []:
        out.append(
            AccountTarget(
                account_id=a.get("account_id"),
                alias=a.get("alias"),
                profile=a.get("profile"),
                role_arn=a.get("role_arn"),
                role_name=a.get("role_name"),
                external_id=a.get("external_id"),
            )
        )
    return out


def _coerce_orgs(raw: list[dict[str, Any]] | None) -> list[OrgTarget]:
    out: list[OrgTarget] = []
    for o in raw or []:
        out.append(
            OrgTarget(
                profile=o.get("profile"),
                role_name=o.get("role_name", DEFAULT_AUDIT_ROLE_NAME),
                external_id=o.get("external_id"),
                exclude_account_ids=list(o.get("exclude_account_ids", [])),
            )
        )
    return out


def load_config(path: str | Path | None) -> AppConfig:
    """Load configuration from a YAML or JSON file, or return defaults if None.

    The file format is intentionally forgiving: top-level keys ``accounts``,
    ``organizations``, ``concurrency``, ``regions``, ``exclude_regions``,
    tag-key overrides, and ``output_dir`` are all optional.
    """
    if path is None:
        return AppConfig()

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")

    text = p.read_text(encoding="utf-8")
    data: dict[str, Any]
    if p.suffix.lower() in (".yaml", ".yml"):
        data = yaml.safe_load(text) or {}
    elif p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        # Try YAML first (a superset of JSON), then JSON.
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            data = json.loads(text)

    cc_raw = data.get("concurrency", {}) or {}
    concurrency = ConcurrencyConfig(
        max_workers=cc_raw.get("max_workers", ConcurrencyConfig.max_workers),
        retries_max_attempts=cc_raw.get("retries_max_attempts", ConcurrencyConfig.retries_max_attempts),
        hard_throttle_cap=cc_raw.get("hard_throttle_cap", ConcurrencyConfig.hard_throttle_cap),
        medium_throttle_cap=cc_raw.get("medium_throttle_cap", ConcurrencyConfig.medium_throttle_cap),
        tokens_per_second=cc_raw.get("tokens_per_second", ConcurrencyConfig.tokens_per_second),
        bucket_capacity=cc_raw.get("bucket_capacity", ConcurrencyConfig.bucket_capacity),
    )
    if "hard_throttle_services" in cc_raw:
        concurrency.hard_throttle_services = list(cc_raw["hard_throttle_services"])

    cfg = AppConfig(
        accounts=_coerce_accounts(data.get("accounts")),
        organizations=_coerce_orgs(data.get("organizations")),
        concurrency=concurrency,
        regions=list(data.get("regions", [])),
        exclude_regions=list(data.get("exclude_regions", [])),
        all_regions=bool(data.get("all_regions", False)),
        include_empty_regions=bool(data.get("include_empty_regions", False)),
        output_dir=data.get("output_dir", "output"),
    )
    for fld, key in [
        ("env_tag_keys", "env_tag_keys"),
        ("owner_tag_keys", "owner_tag_keys"),
        ("data_class_tag_keys", "data_class_tag_keys"),
        ("scope_tag_keys", "scope_tag_keys"),
        ("required_tags", "required_tags"),
    ]:
        if key in data:
            setattr(cfg, fld, list(data[key]))
    return cfg
