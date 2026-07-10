"""Consolidated CSV export of Stage 3 evidence rows (one row per resource×requirement)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from pci_inventory.evidence.runner import EvidenceResult


def write_evidence_csv(result: EvidenceResult, path: str | Path) -> Path:
    """Write all evidence rows to a flat CSV (evidence fields JSON-encoded)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    headers = ["requirement", "sub_requirements", "resource_arn", "resource_id",
               "resource_type", "name", "region", "account_id", "scope_category",
               "scope_confidence", "evidence_fields", "findings", "notes"]
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        for row in sorted(result.rows, key=lambda x: (x.requirement.value, x.resource_arn)):
            w.writerow([
                row.requirement.value, row.sub_requirements, row.resource_arn,
                row.resource_id, row.resource_type, row.name, row.region, row.account_id,
                row.scope_category, row.scope_confidence,
                json.dumps(row.fields, default=str), " | ".join(row.findings), row.notes,
            ])
    return out
