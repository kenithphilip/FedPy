"""PCI DSS v4.0.1 AWS inventory generator (Stage 1: foundation + canonical inventory).

Read-only. Uses only Describe*/List*/Get* AWS API calls. Never creates, modifies,
or deletes any AWS resource.
"""

__version__ = "0.1.0"

# Schema version of the output/inventory.json handoff artifact. Stages 2 and 3
# only ADD keys to each resource record; they never remove or rename Stage 1 keys.
# 1.1.0 (re-audit): added ~29 typed control columns (IMDSv2, MFA, key rotation,
# TLS min version, cert expiry, log retention, vuln/patch, etc.), the
# NOT_COLLECTABLE sentinel, and split backup_retention -> backup_config +
# log_retention_days. Additive only.
# 1.2.0: added instance_type column (EC2 InstanceType / RDS DBInstanceClass).
# Additive only.
INVENTORY_SCHEMA_VERSION = "1.2.0"
