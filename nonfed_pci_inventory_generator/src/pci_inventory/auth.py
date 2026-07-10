"""AWS session management: ambient/SSO default + cross-account assume-role seam.

Design constraints:
- **Single-account default** uses ambient credentials (env, shared config, or an
  ``aws sso login`` session) with zero extra config.
- **boto3 sessions/clients are not thread-safe**, so each worker thread creates
  its own client via :meth:`AccountSession.client`. An :class:`AccountSession`
  holds the immutable identity + a base :class:`boto3.Session`; clients are made
  per call and cached per-thread.
- Cross-account access is via STS AssumeRole (optional). The seam supports a
  configurable role name/ARN and optional ExternalId, per-account isolation, and
  Organizations member-account discovery.

Everything here is read-only: the only mutating-looking call is
``sts:AssumeRole``, which creates no persistent resource.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config as BotoConfig

from pci_inventory.config import AccountTarget, AppConfig, OrgTarget

logger = logging.getLogger("pci_inventory.auth")


def build_boto_config(retries_max_attempts: int, region: str | None = None) -> BotoConfig:
    """Build a botocore Config with adaptive retries and a tool user-agent.

    Adaptive retry mode adds client-side rate limiting that backs off on
    throttling responses — our first line of defence against API limits.
    """
    return BotoConfig(
        region_name=region,
        retries={"mode": "adaptive", "max_attempts": retries_max_attempts},
        user_agent_extra="pci-inventory-generator/0.1.0",
    )


@dataclass
class AccountSession:
    """An authenticated handle for one account, safe to share across threads.

    Clients are created per (thread, service, region) and cached so each worker
    thread gets its own thread-local clients (boto3 clients are not thread-safe).
    """

    account_id: str
    alias: str
    base_session: boto3.Session
    retries_max_attempts: int
    via: str  # "default" | "profile:<name>" | "assume-role:<arn>"
    _local: threading.local = field(default_factory=threading.local, repr=False)

    def client(self, service: str, region: str | None = None) -> Any:
        """Return a thread-local boto3 client for ``service`` in ``region``.

        Global services pass ``region=None`` (or a home region the SDK requires).
        """
        cache: dict[tuple[str, str | None], Any] | None = getattr(self._local, "clients", None)
        if cache is None:
            cache = {}
            self._local.clients = cache
        key = (service, region)
        if key not in cache:
            cache[key] = self.base_session.client(
                service, config=build_boto_config(self.retries_max_attempts, region)
            )
        return cache[key]


def _resolve_identity(session: boto3.Session, retries: int) -> tuple[str, str]:
    """Return (account_id, account_alias) for a session via STS + IAM.

    Alias lookup is best-effort (it may be denied or absent); the account id is
    always available via STS GetCallerIdentity.
    """
    sts = session.client("sts", config=build_boto_config(retries))
    account_id = sts.get_caller_identity()["Account"]
    alias = ""
    try:
        iam = session.client("iam", config=build_boto_config(retries))
        aliases = iam.list_account_aliases().get("AccountAliases", [])
        alias = aliases[0] if aliases else ""
    except Exception as exc:  # noqa: BLE001 - alias is best-effort
        logger.debug("Could not read account alias: %s", exc)
    return account_id, alias


def create_default_session(cfg: AppConfig, profile: str | None = None) -> AccountSession:
    """Create the single-account default session from ambient/SSO credentials."""
    base = boto3.Session(profile_name=profile) if profile else boto3.Session()
    account_id, alias = _resolve_identity(base, cfg.concurrency.retries_max_attempts)
    via = f"profile:{profile}" if profile else "default"
    logger.info("Authenticated to account %s (%s) via %s", account_id, alias or "no-alias", via)
    return AccountSession(
        account_id=account_id,
        alias=alias,
        base_session=base,
        retries_max_attempts=cfg.concurrency.retries_max_attempts,
        via=via,
    )


def _assume_role_session(
    origin: boto3.Session,
    role_arn: str,
    external_id: str | None,
    retries: int,
) -> boto3.Session:
    """Assume a role and return a new boto3 Session with the temp credentials."""
    sts = origin.client("sts", config=build_boto_config(retries))
    kwargs: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "pci-inventory"}
    if external_id:
        kwargs["ExternalId"] = external_id
    creds = sts.assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def create_account_session(cfg: AppConfig, target: AccountTarget) -> AccountSession:
    """Create a session for one configured account target.

    Resolution order: explicit ``role_arn`` -> ``role_name`` (with ``account_id``)
    -> ``profile`` -> ambient credentials.
    """
    retries = cfg.concurrency.retries_max_attempts
    origin = boto3.Session(profile_name=target.profile) if target.profile else boto3.Session()

    role_arn = target.role_arn
    if not role_arn and target.role_name and target.account_id:
        role_arn = f"arn:aws:iam::{target.account_id}:role/{target.role_name}"

    if role_arn:
        base = _assume_role_session(origin, role_arn, target.external_id, retries)
        via = f"assume-role:{role_arn}"
    else:
        base = origin
        via = f"profile:{target.profile}" if target.profile else "default"

    account_id, alias = _resolve_identity(base, retries)
    alias = target.alias or alias
    logger.info("Authenticated to account %s (%s) via %s", account_id, alias or "no-alias", via)
    return AccountSession(
        account_id=account_id,
        alias=alias,
        base_session=base,
        retries_max_attempts=retries,
        via=via,
    )


def discover_org_accounts(cfg: AppConfig, org: OrgTarget) -> list[AccountSession]:
    """Discover active member accounts via Organizations and assume into each.

    Run from a management or delegated-admin account. Accounts in
    ``org.exclude_account_ids`` and SUSPENDED accounts are skipped. Each member
    account is accessed by assuming ``org.role_name``.
    """
    retries = cfg.concurrency.retries_max_attempts
    origin = boto3.Session(profile_name=org.profile) if org.profile else boto3.Session()
    orgs = origin.client("organizations", config=build_boto_config(retries))

    # M7 fix: the calling (management/delegated-admin) account appears in
    # list_accounts but assuming the audit role INTO itself usually fails — use
    # its own ambient session directly so it is never silently omitted.
    origin_account_id, origin_alias = _resolve_identity(origin, retries)

    sessions: list[AccountSession] = []
    paginator = orgs.get_paginator("list_accounts")
    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            acct_id = acct["Id"]
            if acct.get("Status") != "ACTIVE":
                logger.info("Skipping non-active org account %s (%s)", acct_id, acct.get("Status"))
                continue
            if acct_id in org.exclude_account_ids:
                logger.info("Skipping excluded org account %s", acct_id)
                continue
            if acct_id == origin_account_id:
                # Use the ambient session for the calling account.
                sessions.append(
                    AccountSession(
                        account_id=acct_id,
                        alias=origin_alias or acct.get("Name", ""),
                        base_session=origin,
                        retries_max_attempts=retries,
                        via="default (org management/origin account)",
                    )
                )
                logger.info("Including origin/management account %s via ambient session", acct_id)
                continue
            role_arn = f"arn:aws:iam::{acct_id}:role/{org.role_name}"
            try:
                base = _assume_role_session(origin, role_arn, org.external_id, retries)
                _, alias = _resolve_identity(base, retries)
                sessions.append(
                    AccountSession(
                        account_id=acct_id,
                        alias=alias or acct.get("Name", ""),
                        base_session=base,
                        retries_max_attempts=retries,
                        via=f"assume-role:{role_arn}",
                    )
                )
                logger.info("Discovered org account %s (%s)", acct_id, acct.get("Name"))
            except Exception as exc:  # noqa: BLE001 - one bad account must not abort
                logger.warning("Could not assume %s in account %s: %s", org.role_name, acct_id, exc)
    return sessions


def resolve_sessions(cfg: AppConfig, profile: str | None = None) -> list[AccountSession]:
    """Resolve the full list of account sessions to scan, per the config.

    - Default (no accounts/orgs configured): a single ambient/SSO session.
    - ``accounts``: one session per configured target.
    - ``organizations``: discovered member-account sessions (deduped by id).
    """
    if cfg.is_single_account_default:
        return [create_default_session(cfg, profile=profile)]

    sessions: list[AccountSession] = []
    seen: set[str] = set()

    for target in cfg.accounts:
        try:
            s = create_account_session(cfg, target)
            if s.account_id not in seen:
                sessions.append(s)
                seen.add(s.account_id)
        except Exception as exc:  # noqa: BLE001 - one bad target must not abort
            logger.error("Failed to authenticate account target %s: %s", target.account_id, exc)

    for org in cfg.organizations:
        for s in discover_org_accounts(cfg, org):
            if s.account_id not in seen:
                sessions.append(s)
                seen.add(s.account_id)

    if not sessions:
        raise RuntimeError("No account sessions could be established from the provided config.")
    return sessions
