"""Shared utilities: sentinels, time/normalization helpers, structured logging.

These are intentionally dependency-light so every other module can import them
without creating import cycles.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from typing import Any, Iterable


# --------------------------------------------------------------------------- #
# Sentinels — distinguish "empty because inaccessible" from "genuinely absent".
# See research/02-column-schema.md.
# --------------------------------------------------------------------------- #
class Sentinel:
    """Canonical string sentinels used throughout the inventory records.

    The distinction between NOT_COLLECTED and NOT_COLLECTABLE is critical for a
    QSA: the former means "we could have gathered this but didn't this run", the
    latter means "this control is real but is NOT observable from read-only AWS
    APIs" (in-guest, process, or physical) — so a blank must never be read as a
    control gap.
    """

    NA = "N/A"  # attribute does not apply to this resource type
    ACCESS_DENIED = "ACCESS_DENIED"  # auth failure on the call that would populate this
    NOT_COLLECTED = "NOT_COLLECTED"  # not gathered this run (best-effort / out of reach)
    NOT_COLLECTABLE = "NOT_COLLECTABLE"  # control real but not observable read-only (in-guest/process/physical)
    UNKNOWN = "UNKNOWN"  # determination could not be made (e.g. exposure when the deciding call failed)
    PENDING_STAGE2 = "UNDETERMINED — pending Stage 2"  # only for pci_scope

    ALL = frozenset({NA, ACCESS_DENIED, NOT_COLLECTED, NOT_COLLECTABLE, UNKNOWN, PENDING_STAGE2})


# Tri-state boolean for fields that can be Yes / No / N/A.
TriBool = "bool | None"  # None renders as N/A; True->Yes; False->No


GLOBAL_REGION = "GLOBAL"


# --------------------------------------------------------------------------- #
# Time helpers — everything is ISO 8601 UTC.
# --------------------------------------------------------------------------- #
def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime | None) -> str:
    """Render a datetime as ISO 8601 UTC (``YYYY-MM-DDTHH:MM:SSZ``).

    Returns an empty string for ``None`` so callers can leave a field genuinely
    blank. Naive datetimes are assumed to already be UTC.
    """
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_now() -> str:
    """ISO 8601 UTC timestamp string for *now* (used for collection_timestamp)."""
    return iso_utc(utc_now())


# --------------------------------------------------------------------------- #
# Normalization helpers
# --------------------------------------------------------------------------- #
def tags_to_dict(tag_list: Iterable[dict[str, Any]] | None) -> dict[str, str]:
    """Convert an AWS ``[{'Key':..,'Value':..}]`` tag list into a plain dict.

    Handles the common key spellings (``Key``/``Value`` and the lowercase
    ``key``/``value`` used by a few services). Returns ``{}`` if there are no tags.
    """
    out: dict[str, str] = {}
    if not tag_list:
        return out
    for t in tag_list:
        if not isinstance(t, dict):
            continue
        key = t.get("Key", t.get("key"))
        val = t.get("Value", t.get("value", ""))
        if key is not None:
            out[str(key)] = "" if val is None else str(val)
    return out


def first_tag(tags: dict[str, str], candidates: Iterable[str]) -> str:
    """Return the first present tag value among ``candidates`` (case-insensitive).

    Returns an empty string if none of the candidate keys exist.
    """
    lowered = {k.lower(): v for k, v in tags.items()}
    for c in candidates:
        if c.lower() in lowered:
            return lowered[c.lower()]
    return ""


def listify(value: Any) -> list[str]:
    """Coerce a scalar/None/list into a list of strings (drops None/empties)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if value not in (None, "") else []


# --------------------------------------------------------------------------- #
# Resource-policy analysis (replaces fragile substring matching).
# --------------------------------------------------------------------------- #
def analyze_resource_policy(policy: Any) -> dict[str, Any]:
    """Analyze an IAM resource-based policy document for public/anonymous access.

    Accepts a policy as a JSON string or an already-parsed dict. Returns a dict:
        {
          "public": bool,            # an Allow statement grants to "*"/anonymous
          "conditioned": bool,       # that wildcard statement carries a Condition
          "external_principals": [], # non-wildcard principals worth noting
          "parse_error": bool,
        }

    A wildcard principal (string ``"*"`` or ``{"AWS": "*"}`` / ``{"AWS": ["*"]}``)
    on an ``Effect: Allow`` statement is treated as public. If that statement also
    has a ``Condition`` (e.g. ``aws:SourceArn``, ``aws:PrincipalOrgID``), it is
    flagged ``conditioned`` so the caller records "public-with-condition" rather
    than a false-positive bare "public". This is a heuristic for Stage-1
    signalling; precise reachability is a Stage-2 concern.
    """
    result: dict[str, Any] = {
        "public": False,
        "conditioned": False,
        "external_principals": [],
        "parse_error": False,
    }
    if policy in (None, ""):
        return result

    import json as _json

    doc: Any = policy
    if isinstance(policy, str):
        try:
            doc = _json.loads(policy)
        except (ValueError, TypeError):
            result["parse_error"] = True
            return result
    if not isinstance(doc, dict):
        result["parse_error"] = True
        return result

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        has_condition = bool(stmt.get("Condition"))
        wildcard = False
        if principal == "*":
            wildcard = True
        elif isinstance(principal, dict):
            for _key, val in principal.items():
                vals = val if isinstance(val, list) else [val]
                if "*" in vals:
                    wildcard = True
                else:
                    for v in vals:
                        if v and "*" not in str(v):
                            result["external_principals"].append(str(v))
        if wildcard:
            result["public"] = True
            if has_condition:
                result["conditioned"] = True
    return result


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def configure_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure root logging for the tool and return the package logger.

    ``--verbose`` -> DEBUG, ``--quiet`` -> WARNING, default -> INFO. Logs go to
    stderr so stdout stays clean for any future machine-readable use.
    """
    if verbose and quiet:
        raise ValueError("Cannot use --verbose and --quiet together.")
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    handler.formatter.converter = lambda *args: utc_now().timetuple()  # type: ignore[union-attr]

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # boto3/botocore are very chatty at DEBUG; keep them at WARNING unless verbose.
    logging.getLogger("botocore").setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logging.getLogger("pci_inventory")
