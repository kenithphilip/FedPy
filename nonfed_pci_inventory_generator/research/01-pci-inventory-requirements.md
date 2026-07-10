# 01 — PCI DSS v4.0.1 Inventory Requirements Analysis

> **Purpose:** Establish, from the standard itself, exactly what a PCI DSS v4.0.1
> system-component inventory must contain, so the column schema (`02-column-schema.md`)
> and the collectors are provably traceable to a requirement. All standard text is
> **paraphrased** to avoid reproducing copyrighted passages; clause numbers are cited so a
> QSA can verify against their copy of the standard and its testing procedures.
>
> **Sources:** PCI DSS v4.0.1 (published 2024-06) requirements & testing procedures;
> PCI SSC Glossary of Terms, Abbreviations, and Acronyms; AWS service documentation; boto3
> reference. Where a source could not be directly retrieved in this environment, the point is
> labelled **[ASSUMPTION]** and should be confirmed by the QSA.

---

## 1. The anchor requirement — 12.5.1

**Requirement 12.5.1 (paraphrased):** An inventory of system components that are in scope for
PCI DSS — including a description of each component's function/use — is maintained and kept
current.

**Testing procedures (12.5.1, paraphrased):**
- **12.5.1** — Examine the documented inventory and confirm it exists, is maintained, and is
  current.
- Interview personnel to confirm the inventory includes **all** in-scope system components and a
  **description of function/use** for each item.

**What this directly mandates as inventory attributes:**
1. A unique, enumerable identifier for every in-scope system component.
2. A human-meaningful **description of function/use** (purpose/role) per component.
3. Evidence the inventory is **complete** (covers all in-scope components) and **current**
   (kept up to date) — implying capture of timestamps, last-seen/last-activity, and a
   generation date on the artifact itself.

> **Design consequence:** the tool must (a) enumerate components exhaustively and deterministically,
> (b) carry a description/role column, and (c) stamp each record and the workbook with a UTC
> collection time so "current" is demonstrable.

---

## 2. Key definitions (PCI DSS v4.0.1 + Glossary, paraphrased)

### 2.1 "System components"
Any network device, server, computing device, virtual component, cloud component, or piece of
software that is included in or connected to the CDE. The standard's examples explicitly include:
- Systems that **store, process, or transmit** cardholder data (CHD) or sensitive authentication
  data (SAD).
- Systems that provide **security services** (e.g., authentication servers), facilitate
  **segmentation**, or could **impact the security** of the CDE.
- **Virtualization components**: hypervisors, VMs, containers, virtual switches/routers, virtual
  appliances, and the orchestration/management layer.
- **Network components**: firewalls, switches, routers, gateways, load balancers, network
  appliances, wireless access points.
- **Server types**: web, application, database, DNS, mail, proxy, NTP, authentication.
- **Applications**: all purchased and bespoke/custom software, internal and external (incl. APIs).
- **Cloud components**: managed cloud services and the customer-managed resources within them.

> **AWS mapping:** "cloud components" + "virtual components" mean essentially every AWS resource
> the customer can provision is a candidate system component. This is why the coverage matrix
> (`03`) is deliberately broad — including managed services (RDS, Lambda, API Gateway, etc.) and
> the network fabric (VPC/subnet/SG/NACL/route tables), not just EC2.

### 2.2 "In scope for PCI DSS"
A system component is in scope if it is **in the CDE**, is **connected to** the CDE, or **could
impact the security** of the CDE. Scope is determined by data flows and connectivity, and must be
re-validated periodically (12.5.2). **Everything is in scope until segmentation/analysis proves
otherwise.**

> **Stage boundary:** This stage does **not** classify scope. It captures the *inputs* (network
> relationships, exposure signals, IAM connectivity, scope tags). Stage 2 performs reachability /
> IAM-graph analysis and assigns the classification.

### 2.3 CDE — Cardholder Data Environment
The people, processes, and technologies that store, process, or transmit CHD/SAD — **plus** any
system components that are directly connected to, or could impact the security of, that
environment.

### 2.4 "Connected-to" and "security-impacting" systems
Two categories of in-scope-but-not-CDE components the inventory must surface:
- **Connected-to:** systems with network connectivity to the CDE (even indirect), e.g.,
  jump/bastion hosts, admin workstations, shared services, monitoring/log collectors, DNS,
  NTP, patch/AD servers.
- **Security-impacting (NSC-impacting):** systems that could affect the security of the CDE even
  without direct data access, e.g., identity providers, segmentation controllers (firewalls,
  SGs/NACLs/route tables), CI/CD that deploys into the CDE, KMS/secrets stores, logging/monitoring
  that the CDE depends on for detection.

> **Design consequence:** capture full network adjacency (SG rules, NACLs, routes, peering, TGW,
> VPC endpoints, ENIs) and IAM/identity connectivity (who can assume what, resource policies) as
> first-class relationship data so Stage 2 can derive these two categories.

---

## 3. Inventory-adjacent requirements that become columns or signals

| Req | Paraphrased obligation | Inventory implication (column / signal) |
|-----|------------------------|------------------------------------------|
| **6.3.2** | Maintain an inventory of **bespoke and custom software** and third-party/open-source components incorporated into it, to support vuln & patch management. *(New in v4.0.)* | `software_app`, `software_version`, `is_bespoke_software`, component/runtime versions (Lambda runtime, container image, Beanstalk platform). |
| **12.5.2** | PCI DSS scope is **documented and confirmed** at least every 12 months and on significant change — including data flows, CHD locations, all in-scope components, connections, and segmentation effectiveness. | Inventory is the substrate for scope confirmation: needs relationship refs, exposure, segmentation objects. Drives `pci_scope` (Stage 2) and the Cover sheet's completeness caveats. |
| **12.5.2.1** | *(Service providers)* scope confirmation at least every **6 months** and on significant change. | Same as above; cadence note for SP assessments. |
| **2.2.1** | Configuration standards exist for **all** system components. | Inventory must enumerate all components so config-standard coverage can be checked (Stage 3). `resource_type`, `os_platform_engine`. |
| **12.3.4** | Hardware/software technologies reviewed at least every 12 months for vendor **end-of-life / no longer supported**. | `os_platform_engine`, `*_version`, `engine_version`, `creation_date` → EOL analysis. |
| **3.1 / 3.2.1** | Know **where account data is stored**; minimize and inventory storage locations. | Storage/DB resources, `data_classification` (where inferable/tagged), encryption-at-rest. |
| **8.2.1 / 8.2.4 / 8.6** | Inventory and lifecycle of **user / system / application accounts**; manage shared & application accounts. | IAM users/roles/groups, access keys + age, MFA state, service accounts. |
| **8.3.x** | Strong authentication, MFA (8.4/8.5). | `mfa_enabled`, password policy, access-key age. |
| **9.5.1 / 9.5.1.1** | **POI device** inventory (point-of-interaction terminals). | **[ASSUMPTION]** Generally N/A for pure AWS cloud workloads; recorded as out-of-tool-scope unless POI mgmt runs in AWS. Flagged, not collected. |
| **10.2 / 10.3 / 10.5** | **Audit logging** on all system components; protect logs; retention ≥ 12 months (≥ 3 months immediately available). | `logging_enabled`, CloudTrail/Config/flow-log presence, `backup_retention`, log group retention. |
| **10.4** | Review logs (timely, automated mechanisms). | Logging/monitoring objects (CloudWatch alarms, metric filters, EventBridge). |
| **1.2 / 1.3 / 1.4** | Network security controls; restrict traffic to/from CDE; deny-by-default; restrict inbound from untrusted networks. | SGs, NACLs, route tables, IGW/NAT, public exposure signals. |
| **1.2.4 / 1.2.8** | Maintain an **accurate network diagram** and NSC configuration inventory. | Network relationship data underpins diagram generation in later stages. |
| **2.2.7 / 4.2.1** | Encrypt non-console admin access / strong crypto for CHD in transit. | `encryption_in_transit`, TLS policy on LBs/listeners, ACM certs. |
| **3.5 / 3.6 / 3.7** | Render PAN unreadable; key management; key lifecycle. | KMS keys + rotation, CloudHSM, encryption-at-rest flags. |
| **A1 (Multi-tenant SP)** | Logical separation / per-customer scoping. | Account-level tagging; multi-account architecture. |

---

## 4. What "complete and current" forces on the tool

1. **Exhaustive enumeration** across every service in the coverage matrix, every enabled region,
   and every in-scope account — with **explicit, visible gaps** (Errors/Exceptions sheet) so a
   QSA can distinguish "not present" from "could not be read."
2. **Determinism & reproducibility** — stable sort, idempotent, timestamped artifacts.
3. **Traceability** — each column maps to a requirement (see `02`); each resource maps to a source
   API call (see `03`).
4. **Currency evidence** — UTC generation timestamp, per-record `last_modified`/`last_activity`
   where the API exposes it, and creation dates.
5. **Relationship capture** — adjacency for network + IAM so scope (12.5.2) is derivable in Stage 2.

---

## 5. Explicit scope boundaries / assumptions for Stage 1

- **No scope classification** is performed here. `pci_scope` is emitted as
  `UNDETERMINED — pending Stage 2`.
- **No CHD/SAD discovery** (no object/content scanning). `data_classification` is populated only
  from tags or strongly-implied service semantics, and otherwise left `NOT_COLLECTED`.
- **POI / physical devices (9.5.x)** are out of tool scope for cloud-only assessments. **[ASSUMPTION]**
- **On-prem / hybrid** components reachable via Direct Connect / VPN are recorded as connectivity
  objects (DX, VPN, TGW) but on-prem hosts themselves are not enumerable by AWS APIs and are
  flagged as an external-coverage caveat.
- Read-only constraint means some attributes (e.g., in-guest OS package lists) are unavailable
  without SSM Inventory; captured **best-effort** where SSM data is exposed via Get/List, else
  `NOT_COLLECTED`.

---

## 6. Output of this analysis → next artifact

The mandated and adjacent attributes above are consolidated into the **complete column contract**
in `02-column-schema.md`, and each attribute is tied to the **source API** in
`03-service-coverage-matrix.md`.
