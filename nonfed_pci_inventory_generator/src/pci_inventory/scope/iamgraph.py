"""Layer 2 — the IAM / relationship graph (security-impacting without a data path).

Resolves IAM principals → their effective policy statements (inline + attached
managed + resource-based grants) → the resource ARNs they can act on, intersects
with the CDE set, and follows the assume-role chain to a fixpoint. A principal
that can act on a CDE resource is **security-impacting**.

This is a deliberate **static over-approximation** (research/06 §4): it does not
resolve SCP intersection, permission boundaries, or condition keys. It flags
CANDIDATE/DETERMINED access with the *granting statement* recorded — it does not
assert effective access. Honest limits are repeated in output caveats.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pci_inventory.scope.artifact import InventoryIndex

logger = logging.getLogger("pci_inventory.scope.iamgraph")

# Sensitive actions that, against a CDE resource, make a principal
# security-impacting → mapped to the CDE-affecting capability for the basis note.
# Keys are lower-cased exact action names. Wildcard/verb-glob policy actions
# (e.g. "s3:Get*", "ec2:*", "*") are matched against these keys by
# _action_matches_sensitive (re-audit S1a: real policies overwhelmingly use
# wildcard forms, which the previous exact-only matcher missed).
_SENSITIVE_ACTIONS: dict[str, str] = {
    # S3 (read/write/enumerate CDE data)
    "s3:getobject": "read-cde-data",
    "s3:getobjectversion": "read-cde-data",
    "s3:getobjectacl": "read-cde-data",
    "s3:listbucket": "enumerate-cde-bucket",
    "s3:putobject": "write-cde-data",
    "s3:deleteobject": "delete-cde-data",
    "s3:*": "full-cde-bucket",
    # KMS (decrypt/encrypt CDE data, grant chaining)
    "kms:decrypt": "decrypt-cde-data",
    "kms:encrypt": "encrypt-cde-data",
    "kms:generatedatakey": "decrypt-cde-data",
    "kms:generatedatakeywithoutplaintext": "decrypt-cde-data",
    "kms:reencryptfrom": "decrypt-cde-data",
    "kms:reencryptto": "encrypt-cde-data",
    "kms:creategrant": "delegate-cde-key",
    "kms:*": "full-cde-key",
    # Network security controls (segmentation)
    "ec2:authorizesecuritygroupingress": "modify-cde-nsc",
    "ec2:revokesecuritygroupingress": "modify-cde-nsc",
    "ec2:authorizesecuritygroupegress": "modify-cde-nsc",
    "ec2:revokesecuritygroupegress": "modify-cde-nsc",
    "ec2:createroute": "modify-cde-routing",
    "ec2:replaceroute": "modify-cde-routing",
    "ec2:deleteroute": "modify-cde-routing",
    "ec2:createnetworkaclentry": "modify-cde-nacl",
    "ec2:replacenetworkaclentry": "modify-cde-nacl",
    "ec2:runinstances": "launch-into-cde",
    "ec2:modifyinstanceattribute": "modify-cde-instance",
    "ec2:*": "full-cde-ec2",
    # Shell / exec onto CDE compute
    "ssm:startsession": "shell-onto-cde",
    "ssm:sendcommand": "exec-on-cde",
    "ssm:getparameter": "read-cde-secret",
    "ssm:getparameters": "read-cde-secret",
    "ssm:*": "full-cde-ssm",
    "ecs:executecommand": "shell-onto-cde-container",
    # Databases
    "rds:*": "full-cde-db",
    "rds-db:connect": "connect-cde-db",
    "rds:createdbsnapshot": "snapshot-cde-db",
    "rds:modifydbinstance": "modify-cde-db",
    "dynamodb:getitem": "read-cde-table",
    "dynamodb:query": "read-cde-table",
    "dynamodb:scan": "read-cde-table",
    "dynamodb:batchgetitem": "read-cde-table",
    "dynamodb:putitem": "write-cde-table",
    "dynamodb:*": "full-cde-table",
    # Secrets
    "secretsmanager:getsecretvalue": "read-cde-secret",
    "secretsmanager:*": "full-cde-secret",
    # Compute alteration / privilege paths
    "lambda:invokefunction": "invoke-cde-function",
    "lambda:updatefunctioncode": "alter-cde-function",
    "lambda:createfunction": "create-cde-function",
    "lambda:*": "full-cde-function",
    "iam:passrole": "pass-cde-role",
    "sts:assumerole": "assume-cde-role",
}


@dataclass
class IamFinding:
    """A principal with CDE-affecting access (or an assume-chain link to one)."""

    principal_arn: str
    principal_type: str
    cde_resource_arn: str
    capability: str  # e.g. read-cde-data
    via: str  # "inline:NAME" | "managed:ARN" | "resource-policy" | "assume-chain:<arn>"
    statement_ref: str  # human-readable granting statement summary
    confidence: str = "DETERMINED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_arn": self.principal_arn,
            "principal_type": self.principal_type,
            "cde_resource_arn": self.cde_resource_arn,
            "capability": self.capability,
            "via": self.via,
            "statement_ref": self.statement_ref,
            "confidence": self.confidence,
        }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _statements(doc: Any) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        return []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        return [stmts]
    return [s for s in stmts if isinstance(s, dict)]


def _action_capabilities(action: str) -> list[str]:
    """Return the CDE-affecting capabilities an IAM action string confers.

    Handles real-world wildcard forms (S1a): ``*`` (all actions), ``s3:*``
    (service wildcard), and verb globs like ``s3:Get*`` / ``kms:De*``. An action
    pattern matches a sensitive key when, lower-cased, the key would be permitted
    by the pattern (``fnmatch`` semantics). Returns the deduped capability labels.
    """
    a = action.lower()
    if a == "*":
        return ["all-actions"]
    # Exact hit.
    if a in _SENSITIVE_ACTIONS and "*" not in a:
        return [_SENSITIVE_ACTIONS[a]]
    if "*" not in a:
        return []
    # Wildcard pattern: match against every sensitive key it would grant.
    import fnmatch
    caps: list[str] = []
    for key, cap in _SENSITIVE_ACTIONS.items():
        if key.endswith(":*"):
            # Compare service-wildcard keys structurally (avoid '*' matching '*').
            if a == key or (a.endswith(":*") and a.split(":")[0] == key.split(":")[0]):
                caps.append(cap)
            continue
        if fnmatch.fnmatch(key, a):
            caps.append(cap)
    return list(dict.fromkeys(caps))


def _resource_matches(stmt_resources: list[str], cde_arns: set[str]) -> list[str]:
    """Return the CDE ARNs a statement's Resource clause covers (wildcard-aware).

    Handles the common S3 bucket↔object asymmetry (S1a): a CDE seed given as the
    bucket ARN ``arn:aws:s3:::b`` is considered covered by an object-level grant
    on ``arn:aws:s3:::b/*`` (and vice-versa), since object access implies the
    bucket is in scope.
    """
    import fnmatch
    hits: list[str] = []
    for res in stmt_resources:
        if res == "*":
            return list(cde_arns)  # grants on all resources → covers every CDE arn
        for cde in cde_arns:
            if res == cde:
                hits.append(cde)
            elif "*" in res and fnmatch.fnmatch(cde, res):
                hits.append(cde)
            elif res.endswith("/*") and cde == res[:-2]:
                # object-level grant on bucket/* covers the bucket seed
                hits.append(cde)
            elif cde.endswith("/*") and res == cde[:-2]:
                hits.append(cde)
    return list(dict.fromkeys(hits))


class IamGraph:
    """Builds the principal→CDE-resource access graph and assume-role chain."""

    def __init__(self, index: InventoryIndex):
        self.index = index
        # managed policy ARN -> document
        self.managed_docs: dict[str, Any] = {}
        for pol in index.of_type("iam:policy-customer", "iam:policy-aws"):
            data = pol.get("iam_policy_data", {}) or {}
            if data.get("document") is not None:
                self.managed_docs[pol.get("arn", "")] = data["document"]
        self.findings: list[IamFinding] = []
        # role arn -> set of principal arns that can assume it
        self.assumable_by: dict[str, set[str]] = {}
        # principals whose attached managed policy documents could not be resolved
        # (so their access could not be fully evaluated) — surfaced as a caveat.
        self.unresolved_principals: list[str] = []
        self._build_trust_edges()

    def _build_trust_edges(self) -> None:
        for role in self.index.of_type("iam:role"):
            data = role.get("iam_policy_data", {}) or {}
            arn = role.get("arn", "")
            for p in _as_list(data.get("trust_principals")):
                self.assumable_by.setdefault(arn, set()).add(p)

    # ------------------------------------------------------------------ #
    def _principal_statements(self, principal: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        """Yield (via, statement) for a principal's inline + attached managed policies."""
        out: list[tuple[str, dict[str, Any]]] = []
        data = principal.get("iam_policy_data", {}) or {}
        for name, doc in (data.get("inline_policies", {}) or {}).items():
            for s in _statements(doc):
                out.append((f"inline:{name}", s))
        for arn in _as_list(data.get("attached_managed_policies")):
            doc = self.managed_docs.get(arn)
            if doc is not None:
                for s in _statements(doc):
                    out.append((f"managed:{arn.split('/')[-1]}", s))
            else:
                # AWS-managed policy whose doc wasn't captured (unattached filter).
                out.append((f"managed:{arn.split('/')[-1]}", {"_unresolved": arn}))
        return out

    def analyze(self, cde_arns: set[str]) -> list[IamFinding]:
        """Find principals with CDE-affecting access; follow the assume chain."""
        if not cde_arns:
            return []
        directly_impacting: set[str] = set()

        for principal in self.index.of_type("iam:user", "iam:role", "iam:group"):
            arn = principal.get("arn", "")
            ptype = principal.get("resource_type", "")
            for via, stmt in self._principal_statements(principal):
                if stmt.get("Effect") != "Allow":
                    continue  # Deny narrows access — ignored (over-approximation; see caveat).
                if "_unresolved" in stmt:
                    if arn not in self.unresolved_principals:
                        self.unresolved_principals.append(arn)
                    continue
                if self._statement_covers_cde(stmt, cde_arns, arn, ptype, via):
                    directly_impacting.add(arn)

        # Resource-based policies on CDE resources → external principals pulled in.
        self._resource_policy_findings(cde_arns, directly_impacting)

        # Follow the assume-role chain: whatever can assume an impacting principal
        # is itself security-impacting (iterate to fixpoint).
        self._follow_assume_chain(directly_impacting)
        return self.findings

    def _statement_covers_cde(self, stmt: dict[str, Any], cde_arns: set[str],
                              arn: str, ptype: str, via: str) -> bool:
        """Evaluate one Allow statement for CDE-affecting access; record findings.

        Correctly distinguishes Action vs **NotAction** and Resource vs
        **NotResource** (S1a — the previous code merged NotAction into Action,
        inverting the semantics):

        - ``Action`` lists granted actions → match each against the sensitive set.
        - ``NotAction`` grants *everything except* the listed actions → the
          statement confers every sensitive capability whose action is NOT in the
          NotAction set (a broad/near-admin grant), flagged CANDIDATE.
        - ``Resource`` must cover a CDE arn; ``NotResource`` covers the CDE arn
          unless an entry matches it.
        """
        # Resource coverage.
        resources = _as_list(stmt.get("Resource"))
        not_resources = _as_list(stmt.get("NotResource"))
        if resources:
            covered = _resource_matches(resources, cde_arns)
        elif not_resources:
            # Covers every CDE arn NOT excluded by a NotResource entry.
            excluded = set(_resource_matches(not_resources, cde_arns))
            covered = [a for a in cde_arns if a not in excluded]
        else:
            return False
        if not covered:
            return False

        actions = _as_list(stmt.get("Action"))
        not_actions = _as_list(stmt.get("NotAction"))
        found = False

        if actions:
            for action in actions:
                for cap in _action_capabilities(action):
                    for cde_arn in covered:
                        self.findings.append(IamFinding(
                            principal_arn=arn, principal_type=ptype,
                            cde_resource_arn=cde_arn, capability=cap, via=via,
                            statement_ref=f"{action} on {cde_arn} ({via})",
                        ))
                        found = True
        elif not_actions:
            # NotAction = all actions except these. Flag every sensitive capability
            # whose action is NOT excluded — a broad grant — as CANDIDATE.
            excluded = {a.lower() for a in not_actions}
            for sens_action, cap in _SENSITIVE_ACTIONS.items():
                if sens_action in excluded or any(
                    "*" in e and __import__("fnmatch").fnmatch(sens_action, e) for e in excluded
                ):
                    continue
                for cde_arn in covered:
                    self.findings.append(IamFinding(
                        principal_arn=arn, principal_type=ptype,
                        cde_resource_arn=cde_arn, capability=cap,
                        via=via, statement_ref=f"NotAction-broad-grant on {cde_arn} ({via})",
                        confidence="CANDIDATE",
                    ))
                    found = True
        return found

    def _resource_policy_findings(self, cde_arns: set[str], impacting: set[str]) -> None:
        for arn in cde_arns:
            res = self.index.get(arn)
            if not res:
                continue
            data = res.get("iam_policy_data", {}) or {}
            for policy_key in ("resource_based_policy", "key_policy"):
                doc = data.get(policy_key)
                if not doc:
                    continue
                import json as _json
                if isinstance(doc, str):
                    try:
                        doc = _json.loads(doc)
                    except (ValueError, TypeError):
                        continue
                for s in _statements(doc):
                    if s.get("Effect") != "Allow":
                        continue
                    principal = s.get("Principal", {})
                    principals: list[str] = []
                    if isinstance(principal, dict):
                        for v in principal.values():
                            principals.extend(_as_list(v))
                    elif principal == "*":
                        principals = ["*"]
                    else:
                        principals = _as_list(principal)  # bare-string principal fallback
                    # A wildcard principal scoped by a Condition is not truly open
                    # (mirror utils.analyze_resource_policy): record as conditioned.
                    conditioned = bool(s.get("Condition"))
                    for p in principals:
                        is_open = p == "*"
                        cap = ("resource-policy-grant-conditioned"
                               if (is_open and conditioned) else "resource-policy-grant")
                        ref = f"resource policy on {arn} allows {p}"
                        if is_open and conditioned:
                            ref += " (scoped by Condition — verify)"
                        self.findings.append(IamFinding(
                            principal_arn=p, principal_type="external/resource-policy",
                            cde_resource_arn=arn, capability=cap,
                            via=f"resource-policy:{policy_key}",
                            statement_ref=ref,
                            confidence="CANDIDATE" if is_open else "DETERMINED",
                        ))
                        if not is_open:
                            impacting.add(p)

    def _follow_assume_chain(self, impacting: set[str]) -> None:
        # A CDE-accessing role that trusts "*" or :root is the single most
        # important finding — emit it explicitly (S1a B-M3) rather than skipping.
        for role_arn in list(impacting):
            for assumer in self.assumable_by.get(role_arn, set()):
                if assumer == "*" or str(assumer).endswith(":root"):
                    self.findings.append(IamFinding(
                        principal_arn=assumer, principal_type="open-trust",
                        cde_resource_arn=role_arn,
                        capability="open-trust-to-cde-accessing-role",
                        via="assume-chain:open-trust",
                        statement_ref=f"{role_arn} (which has CDE access) trusts {assumer}",
                        confidence="CANDIDATE",
                    ))
        # Direct O(1) lookups by role arn (no full-dict scan per frontier element).
        frontier = set(impacting)
        seen = set(impacting)
        while frontier:
            target = frontier.pop()
            for assumer in self.assumable_by.get(target, set()):
                if assumer in seen or assumer == "*" or str(assumer).endswith(":root"):
                    continue
                seen.add(assumer)
                frontier.add(assumer)
                self.findings.append(IamFinding(
                    principal_arn=assumer, principal_type="assume-chain",
                    cde_resource_arn=target, capability="can-assume-impacting-principal",
                    via=f"assume-chain:{target}",
                    statement_ref=f"{assumer} can assume {target} (which has CDE access)",
                ))

    def security_impacting_arns(self) -> dict[str, list[IamFinding]]:
        """principal_arn -> findings (for the classifier)."""
        out: dict[str, list[IamFinding]] = {}
        for f in self.findings:
            out.setdefault(f.principal_arn, []).append(f)
        return out
