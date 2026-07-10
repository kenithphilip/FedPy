"""Stage 3 evidence models: requirement domains, evidence rows, thresholds.

An :class:`EvidenceRow` is one resource's evidence for one PCI requirement domain
— always traceable to the resource ARN and carrying the Stage 2 scope category +
confidence so evidence can be filtered/prioritized by scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RequirementDomain(str, Enum):
    """The 12 PCI DSS v4.0.1 requirement domains (workbook sheet per domain)."""

    REQ1 = "Req 01 — Network Security Controls"
    REQ2 = "Req 02 — Secure Configuration"
    REQ3 = "Req 03 — Protect Stored Data"
    REQ4 = "Req 04 — Crypto in Transit"
    REQ5 = "Req 05 — Anti-Malware"
    REQ6 = "Req 06 — Secure Software & Patching"
    REQ7 = "Req 07 — Least Privilege"
    REQ8 = "Req 08 — Identity & Authentication"
    REQ9 = "Req 09 — Physical (shared responsibility)"
    REQ10 = "Req 10 — Logging & Monitoring"
    REQ11 = "Req 11 — Security Testing"
    REQ12 = "Req 12 — Program & Scope"

    @property
    def short(self) -> str:
        """Short sheet-safe label, e.g. 'Req 01 NSC'."""
        return self.value.split(" — ")[0]


# Excel sheet title per domain (<=31 chars).
_SHEET_TITLES = {
    RequirementDomain.REQ1: "Req 01 NSC",
    RequirementDomain.REQ2: "Req 02 Secure Config",
    RequirementDomain.REQ3: "Req 03 Data at Rest",
    RequirementDomain.REQ4: "Req 04 Crypto in Transit",
    RequirementDomain.REQ5: "Req 05 Anti-Malware",
    RequirementDomain.REQ6: "Req 06 Software & Patch",
    RequirementDomain.REQ7: "Req 07 Least Privilege",
    RequirementDomain.REQ8: "Req 08 Identity & Auth",
    RequirementDomain.REQ9: "Req 09 Physical",
    RequirementDomain.REQ10: "Req 10 Logging",
    RequirementDomain.REQ11: "Req 11 Testing",
    RequirementDomain.REQ12: "Req 12 Program & Scope",
}


def sheet_title(domain: RequirementDomain) -> str:
    return _SHEET_TITLES[domain]


@dataclass
class EvidenceRow:
    """One resource's evidence for one requirement domain.

    ``fields`` holds the requirement-relevant evidence as ordered key→value pairs
    (already-collected inventory data + any attached follow-up findings). Every row
    carries the parent resource identity and the Stage 2 scope classification.
    """

    requirement: RequirementDomain
    sub_requirements: str  # e.g. "1.2, 1.3"
    resource_arn: str
    resource_id: str
    resource_type: str
    name: str
    region: str
    account_id: str
    scope_category: str
    scope_confidence: str
    fields: dict[str, Any] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)  # attached security-service findings
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement": self.requirement.value,
            "sub_requirements": self.sub_requirements,
            "resource_arn": self.resource_arn,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "name": self.name,
            "region": self.region,
            "account_id": self.account_id,
            "scope_category": self.scope_category,
            "scope_confidence": self.scope_confidence,
            "fields": self.fields,
            "findings": self.findings,
            "notes": self.notes,
        }


@dataclass
class EvidenceThresholds:
    """Configurable thresholds for derived indicators (conventional defaults).

    These drive *indicators*, not pass/fail verdicts. All are documented in the
    workbook and overridable via the evidence config.
    """

    stale_credential_days: int = 90  # access-key age / last-used staleness
    cert_expiry_warn_days: int = 30  # cert/key expiring soon (warn)
    cert_expiry_notice_days: int = 90  # cert/key expiring (notice)
    log_retention_min_days: int = 365  # PCI 10.5.1 ≥ 12 months

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "EvidenceThresholds":
        if not data:
            return cls()
        return cls(
            stale_credential_days=int(data.get("stale_credential_days", 90)),
            cert_expiry_warn_days=int(data.get("cert_expiry_warn_days", 30)),
            cert_expiry_notice_days=int(data.get("cert_expiry_notice_days", 90)),
            log_retention_min_days=int(data.get("log_retention_min_days", 365)),
        )


# Scope categories considered "in scope" for indicator breakdowns.
IN_SCOPE_CATEGORIES = ("CDE", "connected-to", "security-impacting")
