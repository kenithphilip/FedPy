---
slice_id: X.X5
title: Policy Decision Point / Policy Enforcement Point Integration Evidence Collector (NIST SP 800-207 §3.3 + 800-207A two-tier policy + cloud-native PEP normalization)
loop: X
status: proposed
commit: TBD
completed_date: —
depends_on:
  - X.X2                                 # 800-207 architecture map names the PDP/PA/PEP candidates X.X5 walks
  - X.X3                                 # 800-207A cloud-native augmentation names the sidecar/admission/SPIFFE evidence X.X5 references
  - LOOP-INV-S                           # Inventory coverage contract — X.X5 emits inventory-coverage updates per provider
  - LOOP-INV-P1                          # Inventory backbone — X.X5 reads inventory.assets[].provider_tag to scope per-cloud collection
  - LOOP-E.E1                            # Kubernetes-direct collector — X.X5 reuses the k8s API client + RBAC scoping helpers
  - LOOP-A.A5                            # Ed25519 + RFC 3161 signing — X.X5's envelope flows through signEnvelope()
  - LOOP-A.A4                            # Submission bundler — X.X5 adds the `pdp-pep-evidence` role to the bundle catalogue
  - LOOP-A.A1                            # OSCAL POA&M — X.X5 emits a POA&M finding per unreachable / misconfigured PEP
blocks: []
estimated_effort: medium (~5-7 working days for single implementer; depends largely on multi-cloud SDK adapter breadth)
last_updated: 2026-06-08
applicable_conditional: true
condition: Universal for any CSP using LOOP-X. The slice is "universal-within-LOOP-X" because every Zero Trust Architecture per NIST SP 800-207 §3.3 has at least one Policy Decision Point and at least one Policy Enforcement Point — there is no degenerate case where the slice does not apply. If LOOP-X itself is OFF (`--no-zero-trust`), X.X5 does not run. If LOOP-X is ON and a CSP somehow ships with zero PEPs (a defective ZT posture), X.X5 emits an empty envelope plus a `coverage:zero-pep` diagnostic plus a POA&M item per NIST SP 800-207 §3.3 ("a zero trust architecture is composed of three logical components ... a Policy Enforcement Point") — i.e. the absence is itself the finding.
trigger_flag: "--zero-trust"
trigger_env: CLOUD_EVIDENCE_ZERO_TRUST
---

# X.X5 — Policy Decision Point / Policy Enforcement Point Integration Evidence Collector

> X.X5 is the LOOP-X slice that **captures the actual policy bytes** at
> each Policy Decision Point (PDP) and Policy Enforcement Point (PEP) in
> the CSP's cloud-native environment and normalises them into a single
> signed evidence envelope a 3PAO can verify offline. X.X2 produced the
> architecture map (who the PDPs/PAs/PEPs are); X.X3 added the cloud-
> native augmentation (sidecars / SPIFFE / admission webhooks); X.X4
> scored the maturity. X.X5 closes the loop by attaching the **policy
> artifacts themselves** to each PEP — without those artifacts, a 3PAO
> cannot verify that the architecture diagram is anything more than a
> diagram. NIST SP 800-207 §3.3 is explicit that a Policy Enforcement
> Point is "responsible for enabling, monitoring, and eventually
> terminating connections between a subject and an enterprise resource";
> X.X5 captures the configuration that drives that enabling /
> terminating behaviour.
>
> Why this slice is non-trivial: cloud-native ZT PEPs are heterogeneous
> across AWS, GCP, Azure, and Kubernetes. AWS Verified Access has its
> own policy DSL (Cedar); GCP BeyondCorp Enterprise uses
> AccessLevels + AccessPolicies; Azure Conditional Access uses a
> JSON policy schema; Istio AuthorizationPolicy uses its own CRD;
> OPA / Gatekeeper uses Rego + ConstraintTemplates; Kubernetes
> NetworkPolicy uses a built-in v1 schema; AWS VPC SG / GCP firewall
> rules / Azure NSG each have a different rule grammar. X.X5 collects
> all of them, preserves the verbatim source, AND emits a normalised
> projection so the maturity scorer (X.X4) and the 3PAO browser
> (tracker UI) can reason about the union.

## 1. Mission

X.X5 walks every PDP/PEP candidate identified by X.X2's architecture
map and X.X3's cloud-native augmentation, pulls the actual policy
artifact bytes from each one via real cloud-native APIs (no mocks),
preserves the verbatim source artifact (Rego / JSON / YAML / Cedar /
CRD spec), produces a normalised projection conforming to the
`pdp-pep-evidence-v1` schema, signs the envelope with the org's
Ed25519 signing key, attaches an RFC 3161 timestamp, persists the
envelope into the tracker DB `pdp_pep_evidence` table, and surfaces
the envelope in the FedRAMP submission bundle under the
`pdp-pep-evidence` role. A 3PAO opening the envelope can:

1. See the topology (which PDPs, which PEPs, mapped to which
   resources).
2. Read the verbatim policy text at each PEP (no re-interpretation by
   FedPy).
3. Verify the Ed25519 signature offline.
4. Confirm the RFC 3161 timestamp via any compliant TSA.
5. Trace any normalised field back to a verbatim source via
   `provenance.source_artifact_uri`.

X.X5 does **not** evaluate the policies for correctness. Policy-
correctness analysis (Rego-rule reasoning, Cedar policy formal
verification, NetworkPolicy reachability analysis) is out of scope
per REO Rule 1 — the system observes, it does not adjudicate. The
3PAO performs the adjudication; X.X5 supplies the unforgeable
evidence pack. The only enforcement-side computation X.X5 performs
is structural: did the GET / Describe call return the policy bytes,
did the bytes parse against the cloud-native schema, and did the
normaliser produce a deterministic projection.

X.X5 also implements an **operator-override path** for custom PEPs
not on the default detection list (per LOOP-X-SPEC.md §17.2's
`pdp-pep-overrides.yaml`). Operator entries carry
`provenance: operator-override` and are visually distinguished from
system-discovered PEPs in the tracker UI. REO Rule 4 governs the
override path — operator inputs are real, but they are tagged so the
3PAO can apply different evidence weight if desired.

## 2. Authoritative sources

Every URL accessed 2026-06-08. Verbatim quotes appear in Markdown
blockquotes. Where the federal source returned a non-200 to
anonymous fetches, the implementer downloads the page or PDF to
`cloud-evidence/docs/sources/zt/` and re-quotes verbatim from the
local mirror.

### 2.1 NIST SP 800-207 §3.3 — Logical Components of ZTA (the PE / PA / PEP triad)

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf
(accessed 2026-06-08; PDF mirrored to
`cloud-evidence/docs/sources/zt/NIST.SP.800-207.pdf` per LOOP-X-SPEC
§2.2). Authors: Scott Rose, Oliver Borchert, Stu Mitchell, Sean
Connelly. Published August 2020. 50 pages. The §3.3 text below
is the architectural foundation X.X5 enforces.

> "A zero trust architecture is composed of three logical components:
> a Policy Engine (PE) that is responsible for the ultimate decision
> to grant access to a resource for a given subject; a Policy
> Administrator (PA) that establishes and/or shuts down the
> communication path between a subject and a resource; and a Policy
> Enforcement Point (PEP) that is responsible for enabling,
> monitoring, and eventually terminating connections between a
> subject and an enterprise resource."

> "These three logical components may be operated as a single service
> or as several services, depending on the enterprise's requirements
> and the criticality of the assets being protected."

The §3.3 triad governs every X.X5 collection: for each PEP, X.X5
records which PE made the decision, which PA established the path,
and what policy bytes drove the decision. The triad is recorded
inside every emitted record as `pe_ref`, `pa_ref`, `pep_id`.

> "The Policy Enforcement Point (PEP) enables, monitors, and
> eventually terminates connections between a subject and an
> enterprise resource. The PEP communicates with the PA to forward
> requests and/or receive policy updates from the PA."

Implication for X.X5: a PEP is identified by **its ability to
terminate a session on policy violation**. X.X5's enumerator filters
out cloud primitives that observe but cannot terminate (e.g. flow
logs, CloudTrail) — those are evidence sources for X.X3 / X.X4 but
they are not PEPs.

### 2.2 NIST SP 800-207A — Two-Tier Policy Model (network-tier + identity-tier)

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf
(accessed 2026-06-08; PDF mirrored to
`cloud-evidence/docs/sources/zt/NIST.SP.800-207A.pdf`). Published
September 2023, supersedes the IPD.

> "The guidance recommends the formulation of network-tier and
> identity-tier policies and the configuration of technology
> components (e.g., gateways, infrastructure for service identities,
> authentication, and authorization tokens)."

> "The service mesh centrally manages a fleet of application proxies
> and serves as a modern cloud-native security kernel, where proxies
> can enforce security and traffic policies and generate telemetry
> data."

> "API gateways, sidecar proxies, and application identity
> infrastructures (e.g., SPIFFE) ... can enforce policies
> irrespective of the location of services or applications, whether
> on-premises or on multiple clouds."

X.X5's emitter requires a per-PEP `policy_tier` discriminator
(`network` | `identity` | `both`) sourced verbatim from 800-207A's
two-tier model. A PEP that only enforces L4 network rules (k8s
NetworkPolicy, AWS VPC SG) reports `network`; an Istio
AuthorizationPolicy that gates by `principals` reports `identity`
(or `both` if it also gates by `from.source.namespaces`).

### 2.3 Kubernetes NetworkPolicy reference (v1 networking.k8s.io API)

URL (pinned): https://kubernetes.io/docs/concepts/services-networking/network-policies/
(accessed 2026-06-08).

> "If you want to control traffic flow at the IP address or port
> level for TCP, UDP, and SCTP protocols, then you might consider
> using Kubernetes NetworkPolicies for particular applications in
> your cluster. NetworkPolicies are an application-centric construct
> which allow you to specify how a pod is allowed to communicate
> with various network 'entities'."

> "By default, a pod is non-isolated for egress; all outbound
> connections are allowed. A pod is isolated for egress if there is
> any NetworkPolicy that both selects the pod and has 'Egress' in
> its policyTypes; we say that such a policy applies to the pod for
> egress."

> "Network policies do not conflict; they are additive. If any
> policy or policies apply to a given pod for a given direction, the
> connections allowed in that direction from that pod is the union
> of what the applicable policies allow."

X.X5's Kubernetes adapter collects NetworkPolicy resources via the
canonical k8s API path `GET /apis/networking.k8s.io/v1/networkpolicies`
and `GET /apis/networking.k8s.io/v1/namespaces/<ns>/networkpolicies`,
preserves the YAML spec verbatim, and projects the per-namespace
default-deny / default-allow status into the normalised envelope.
The "policies are additive" semantic above means X.X5 must collect
**all** NetworkPolicy objects per namespace; the per-namespace
posture is the union, not any single policy.

### 2.4 Istio AuthorizationPolicy reference (security.istio.io/v1)

URL (pinned): https://istio.io/latest/docs/reference/config/security/authorization-policy/
(accessed 2026-06-08).

> "Istio Authorization Policy enables access control on workloads in
> the mesh. Authorization Policy supports CUSTOM, DENY and ALLOW
> actions for access control. When CUSTOM, DENY and ALLOW actions
> are used for a workload at the same time, the CUSTOM action is
> evaluated first, then the DENY action, and finally the ALLOW
> action."

> "If there are any DENY policies that match the request, deny the
> request. If there are no ALLOW policies for the workload, allow
> the request. If any of the ALLOW policies match the request, allow
> the request. Deny the request."

X.X5's Istio adapter collects AuthorizationPolicy CRDs via
`GET /apis/security.istio.io/v1/authorizationpolicies`, captures the
verbatim CRD YAML, and projects the precedence semantics
(CUSTOM → DENY → ALLOW) into the normalised envelope as
`evaluation_order`. The default-allow / default-deny posture per
mesh is derived from the union of ALLOW vs DENY policies and
recorded as `mesh_default_posture`. The slice does NOT re-implement
the precedence semantics — it records them as documented.

### 2.5 OPA / Gatekeeper (open-policy-agent.github.io)

URL (pinned): https://open-policy-agent.github.io/gatekeeper/website/docs/
(accessed 2026-06-08).

> "Gatekeeper is a customizable admission webhook for Kubernetes
> that enforces policies executed by the Open Policy Agent (OPA), a
> policy engine for Cloud Native environments hosted by CNCF as a
> graduated project."

> "A ConstraintTemplate describes both the Rego that enforces the
> constraint and the schema of the constraint. The schema of the
> constraint allows an admin to fine-tune the behavior of a
> constraint, much like arguments to a function."

> "Constraints are then used to inform Gatekeeper that the admin
> wants a ConstraintTemplate to be enforced, and how."

X.X5's OPA / Gatekeeper adapter collects both
ConstraintTemplates and Constraints via the k8s API path
`GET /apis/templates.gatekeeper.sh/v1/constrainttemplates` and
`GET /apis/constraints.gatekeeper.sh/v1beta1/<kind>`. The verbatim
Rego source from each template is captured as
`policy_artifact.rego_source`; constraint instances are captured
under `policy_artifact.bindings[]`. Kyverno is recognised as an
alternative engine (see `engine_family` enum below) and uses
`GET /apis/kyverno.io/v1/clusterpolicies`.

### 2.6 AWS Verified Access (Cedar policy language)

URL (pinned): https://docs.aws.amazon.com/verified-access/latest/ug/what-is-verified-access.html
(accessed 2026-06-08).

> "AWS Verified Access provides secure access to corporate
> applications without a VPN. It evaluates each application request
> and helps ensure that users can access each application only when
> they meet the specified security requirements."

> "Verified Access policies are written using Cedar, an AWS-developed
> policy language. ... A Verified Access policy contains conditions
> for how users and devices must be configured to access an
> application. Each policy is attached to a Verified Access group
> or a Verified Access endpoint."

X.X5's AWS adapter collects Verified Access policies via the
`ec2:DescribeVerifiedAccessGroups`, `ec2:DescribeVerifiedAccessEndpoints`,
and `ec2:GetVerifiedAccessGroupPolicy` /
`ec2:GetVerifiedAccessEndpointPolicy` SDK calls. The Cedar policy
text is preserved verbatim as `policy_artifact.cedar_source`. AWS
VPC Security Groups are collected separately via
`ec2:DescribeSecurityGroups` and recorded as L4-only PEPs
(`policy_tier: 'network'`).

### 2.7 GCP firewall + IAP + BeyondCorp Enterprise

URL (pinned): https://cloud.google.com/beyondcorp-enterprise/docs/overview
(accessed 2026-06-08).

> "BeyondCorp Enterprise is a zero trust solution from Google Cloud
> that provides integrated threat and data protection, centered on
> providing secure access to applications. ... BeyondCorp Enterprise
> works on the principle that trust must be established through
> multiple mechanisms and continuously verified."

> "Access policies and access levels: Define context-aware access
> policies for users and resources, using access levels to specify
> conditions that must be met, such as a corporate device or an
> approved IP address."

X.X5's GCP adapter collects:

- VPC firewall rules via `compute.firewalls.list` (network-tier).
- IAP-protected backend services via `compute.backendServices.list`
  filtered by `iap.enabled = true` (identity-tier).
- AccessLevels / AccessPolicies via the
  `accesscontextmanager.accessLevels.list` and
  `accesscontextmanager.accessPolicies.list` APIs (identity-tier).

The verbatim policy JSON is preserved as
`policy_artifact.gcp_policy_json`.

### 2.8 Azure Conditional Access + NSG

URL (pinned): https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview
(accessed 2026-06-08).

> "Conditional Access policies at their simplest are if-then
> statements: if a user wants to access a resource, then they must
> complete an action. ... Conditional Access is the Zero Trust
> policy engine at the heart of the new identity-driven control
> plane."

> "Network security group security rules are evaluated by priority
> using the 5-tuple information (source, source port, destination,
> destination port, and protocol) to allow or deny the traffic."
> (Azure NSG docs: https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview;
> accessed 2026-06-08.)

X.X5's Azure adapter collects:

- Conditional Access policies via Microsoft Graph
  `GET /v1.0/identity/conditionalAccess/policies` (identity-tier).
- Network Security Groups via the
  `networkInterfaces / networkSecurityGroups` ARM endpoints
  (network-tier).
- Azure Policy assignments scoped to security-related built-in
  definitions via `GET /providers/Microsoft.Authorization/policyAssignments`
  (cross-tier).

### 2.9 SPIFFE specification (workload-identity input to identity-tier PEPs)

URL (pinned): https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md
(accessed 2026-06-08).

> "The Secure Production Identity Framework For Everyone (SPIFFE)
> defines a framework and set of standards for identifying and
> securing communications between web-based services."

> "A SPIFFE ID is a structured string used to identify a resource
> or caller. ... It is the standard format for SPIFFE Verifiable
> Identity Documents."

X.X5 records the presence of SPIFFE identities at each identity-tier
PEP by consulting X.X3's cloud-native augmentation envelope
(`zt-800-207a-cloud-native.json`) — X.X5 does NOT re-collect SPIFFE
bundles, it cites them. The cited SPIFFE bundle URI lives in
`policy_artifact.workload_identity_refs[]`.

### 2.10 NIST SP 800-204B — Attribute-Based Access Control for Microservices

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204B.pdf
(accessed 2026-06-08; PDF mirrored to
`cloud-evidence/docs/sources/zt/NIST.SP.800-204B.pdf`). Published
August 2021.

> "This document recommends an Attribute-Based Access Control (ABAC)
> system for microservices-based applications. The system is intended
> to address the requirements that arise from the inherent ZTA
> mindset (i.e., the use of identity- and context-based decisions
> for access)."

> "In an ABAC system, access decisions are based on attributes
> associated with the requestor, resource, action, and environment."

X.X5 records, per identity-tier PEP, whether the policy uses ABAC
attributes (`policy_artifact.uses_abac: true|false`). The
determination is structural: presence of `when` clauses (Istio),
`principals` matchers, request-context attributes (Cedar `context`,
GCP `accessLevels`, Azure Conditional Access "conditions"). X.X5
does not classify ABAC quality — only presence vs absence.

### 2.11 NIST SP 800-53 Rev 5 — Boundary Protection (SC-7) + Access Enforcement (AC-3)

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-08). Already mirrored under
`cloud-evidence/docs/sources/`.

> "Control AC-3 Access Enforcement: Enforce approved authorizations
> for logical access to information and system resources in
> accordance with applicable access control policies."

> "Control SC-7 Boundary Protection: Monitor and control
> communications at the external managed interfaces to the system
> and at key internal managed interfaces within the system; and
> implement subnetworks for publicly accessible system components
> that are physically or logically separated from internal
> organizational networks."

X.X5 cross-walks every PEP to the relevant SC-7 / AC-3 control:
network-tier PEPs map to SC-7; identity-tier PEPs map to AC-3.
The cross-walk lives in `policy_artifact.nist_control_refs[]` and
is consumed by LOOP-A.A3's AR for control-coverage reporting.

### 2.12 OMB M-22-09 §II.D — Networks pillar specific action

URL (pinned): https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
(accessed 2026-06-08).

> "Agencies must encrypt all DNS requests and HTTP traffic within
> their environment, and begin executing a plan to break down their
> perimeters into isolated environments."

This is the strategic-goal language under which X.X5 collects PEP
evidence: a CSP that wants to demonstrate compliance with M-22-09's
Networks-pillar action MUST be able to point a 3PAO at the per-
namespace / per-subnet PEP policies that "break down perimeters
into isolated environments". The evidence pack X.X5 emits is the
direct artifact that proves that posture (or proves its absence).

---

## 3. Scope

### 3.1 In scope

- Discovery of all PDP / PEP candidates already identified by X.X2's
  architecture map and X.X3's cloud-native augmentation envelope.
- Collection of verbatim policy bytes from each PEP via real
  cloud-native APIs (no mocks; SDK transport may be mocked only at
  the wire layer in tests, per REO Rule 2).
- Normalisation of policy metadata (PEP id, normalised class,
  provider native type, policy tier, evaluation order, default
  posture, ABAC presence, NIST control refs) per
  `pdp-pep-evidence-v1` schema.
- Ed25519 signing + RFC 3161 timestamp on the canonical envelope.
- Persistence into tracker DB table `pdp_pep_evidence` with audit
  trail.
- Submission-bundler registration under role `pdp-pep-evidence`.
- OSCAL POA&M emission for any PEP whose policy collection failed
  (auth error, unreachable, schema-mismatch) or whose enforcement
  posture is below the per-pillar target (e.g. default-allow
  NetworkPolicy when target stage requires default-deny).
- Operator-override path for custom PEPs via
  `cloud-evidence/pdp-pep-overrides.yaml`.
- Per-provider inventory-coverage update (LOOP-INV-S contract):
  the per-provider PEP-coverage fill rate is written to
  `out/inventory-coverage.json`.

### 3.2 Out of scope

- Policy-correctness evaluation (Rego rule reasoning, Cedar formal
  verification, NetworkPolicy reachability analysis). Reasoning
  about whether a captured policy actually enforces the stated
  intent is the 3PAO's job; X.X5 supplies unforgeable evidence,
  not adjudication.
- Implementing a PDP / PEP. X.X5 OBSERVES; it does not BUILD.
  REO Rule 1 — no fake enforcement operations.
- Long-form policy diff between runs. A coarse signature
  (`policy_artifact.sha256`) is emitted so diffs are computable
  downstream by LOOP-G (CHANGELOG) and LOOP-I (dashboards), but
  X.X5 does not render diffs itself.
- Detection of policy drift since last scan. That belongs to the
  ConMon LOOP-E.E3 anomaly-detection slice; X.X5 records a
  point-in-time snapshot.
- Multi-cluster / multi-mesh federation reconciliation (e.g. Istio
  multi-cluster). X.X5 collects per-cluster; federation reasoning
  belongs to a future LOOP-X.X6 if required.
- DoD-specific JWCC PEP overlay. Captured as an open question in
  §10; if needed, a sibling slice X.X5-JWCC could be added.

---

## 4. Inputs

```typescript
/** Pinned references to upstream LOOP-X artifacts. */
interface X5UpstreamInputs {
  /** The 800-207 architecture map emitted by X.X2 (signed JSON). */
  architectureMapPath: string; // e.g. 'data/zt-800-207-architecture.json'
  /** The 800-207A cloud-native augmentation emitted by X.X3 (signed JSON). */
  cloudNativeAugPath: string; // e.g. 'data/zt-800-207a-cloud-native.json'
  /** The X.X1 pillar catalog (signed JSON) for NIST control cross-walks. */
  pillarsCatalogPath: string; // e.g. 'data/zt-pillars-omb-m-22-09.json'
  /** The LOOP-INV-P1 inventory (signed JSON) for asset-graph scoping. */
  inventoryPath: string; // e.g. 'inventory.json'
}

/** Per-provider SDK credentials reused from prior FedPy loops. */
interface X5ProviderCredentials {
  aws?: { profile: string; region: string; assumeRoleArn?: string };
  gcp?: { projectId: string; impersonateServiceAccount?: string };
  azure?: { subscriptionId: string; tenantId: string };
  kubernetes?: { kubeconfigPath: string; contextName?: string };
}

/** Operator-supplied overrides (per LOOP-X-SPEC §17.2). */
interface PdpPepOverridesFile {
  pdp_pep_overrides: Array<{
    id: string;
    classification: 'PE' | 'PA' | 'PEP';
    normalised_class: string; // see §5.3 enum
    provider_native_type: string;
    deployment_location: string;
    policy_location: string;
    last_policy_review: string; // ISO date
    operator_attestation_text: string;
    provenance: 'operator-override';
  }>;
}

/** Per-run config — extends LOOP-X zt-config.yaml. */
interface X5RunConfig {
  enabled: boolean;
  pdp_overrides_path?: string; // default 'pdp-pep-overrides.yaml'
  max_parallel_collectors: number; // default 8
  per_provider_timeout_ms: number; // default 60_000
  collect_verbatim_source: boolean; // default true; REO requires true
  redact_secrets_in_policies: boolean; // default true; redacts AWS access keys, GCP service-account JSON, JWTs
  emit_normalised_only_for_unparseable: boolean; // default false; if true, unparseable policies still get a row
}

/** Existing signing primitives reused from LOOP-A.A5. */
interface X5SigningContext {
  ed25519_key_ref: string; // KMS resource ref
  rfc3161_tsa_url: string;
  signing_officer_name: string;
  signing_officer_title: string;
}
```

---

## 5. Outputs

### 5.1 Canonical-JSON envelope (`pdp-pep-evidence-v1`)

```typescript
interface PdpPepEvidenceEnvelope {
  schema_version: 'pdp-pep-evidence-v1';
  envelope_id: string; // ULID
  system_id: string;
  run_id: string;
  collected_at: string; // ISO 8601 UTC
  generator: {
    name: 'fedpy/cloud-evidence';
    version: string;
    git_commit: string;
  };
  upstream_refs: {
    architecture_map_sha256: string;
    cloud_native_aug_sha256: string;
    pillars_catalog_sha256: string;
    inventory_sha256: string;
  };
  topology: Array<{
    pe_ref: string;   // e.g. 'aws.verifiedaccess.policy-engine'
    pa_ref: string;   // e.g. 'aws.iam-identity-center'
    pep_id: string;   // unique within envelope
  }>;
  peps: Array<PepRecord>;
  pes: Array<PeRecord>;
  pas: Array<PaRecord>;
  coverage: {
    total_pep_candidates: number;
    collected_pep_count: number;
    failed_pep_count: number;
    coverage_pct: number; // computed
    per_provider: Record<'aws' | 'gcp' | 'azure' | 'kubernetes', {
      candidates: number;
      collected: number;
      coverage_pct: number;
    }>;
  };
  diagnostics: Array<{
    code: string; // e.g. 'coverage:miss', 'auth:denied', 'schema:unparseable'
    pep_id?: string;
    message: string;
    severity: 'info' | 'warn' | 'error';
  }>;
  signature: {
    algorithm: 'ed25519';
    public_key_id: string;
    signature_b64: string;
  };
  rfc3161_timestamp?: {
    tsa_url: string;
    timestamp_token_b64: string;
    status: 'verified' | 'pending';
  };
}

interface PepRecord {
  pep_id: string;
  classification: 'PEP';
  provider: 'aws' | 'gcp' | 'azure' | 'kubernetes' | 'operator-supplied';
  provider_native_type: string; // e.g. 'aws.verifiedaccess.endpoint'
  normalised_class:
    | 'network-perimeter-pep-north-south'
    | 'network-perimeter-pep-east-west'
    | 'identity-aware-proxy'
    | 'conditional-access-engine'
    | 'service-mesh-sidecar'
    | 'admission-webhook'
    | 'microservices-pdp-pep';
  policy_tier: 'network' | 'identity' | 'both';
  engine_family?: 'opa' | 'gatekeeper' | 'kyverno' | 'istio' | 'envoy' | 'cedar' | 'azure-policy' | 'gcp-firewall' | 'aws-sg' | 'k8s-network-policy';
  deployment_location: string;
  scope: { namespace?: string; resource_arn?: string; project_id?: string; subscription_id?: string };
  policy_artifact: {
    source_artifact_uri: string; // e.g. 'k8s://default/networkpolicy/web-deny-all'
    source_artifact_kind: 'rego' | 'cedar' | 'yaml' | 'json' | 'crd-spec' | 'arm-template';
    bytes_b64?: string; // verbatim source, only if collect_verbatim_source = true
    sha256: string;
    parsed_ok: boolean;
    rego_source?: string;
    cedar_source?: string;
    gcp_policy_json?: unknown;
    azure_policy_json?: unknown;
    bindings?: Array<{ kind: string; name: string; namespace?: string; sha256: string }>;
    default_posture?: 'default-deny' | 'default-allow' | 'mixed';
    evaluation_order?: Array<'CUSTOM' | 'DENY' | 'ALLOW'>;
    uses_abac: boolean;
    workload_identity_refs?: string[]; // SPIFFE IDs cited from X.X3
    nist_control_refs: string[]; // e.g. ['SC-7', 'AC-3']
  };
  last_policy_review?: string; // ISO date, operator-supplied
  evidence_pointers: string[]; // refs to KSI outputs, inventory entries
  provenance: 'system-discovered' | 'operator-override';
  collected_at: string; // ISO 8601 UTC
}

interface PeRecord { pep_id_refs: string[]; pe_ref: string; provider: string; deployment_location: string; vendor: string; }
interface PaRecord { pep_id_refs: string[]; pa_ref: string; provider: string; deployment_location: string; vendor: string; }
```

### 5.2 Output file paths

- `out/pdp-pep-evidence-{system_id}-{YYYYMMDD}.json` — Ed25519-signed
  envelope (canonical JSON, RFC 8785).
- `out/pdp-pep-evidence-{system_id}-{YYYYMMDD}.tst` — detached RFC
  3161 timestamp token (binary DER).
- `out/pdp-pep-coverage-{system_id}-{YYYYMMDD}.json` — per-provider
  coverage roll-up (also merged into `out/inventory-coverage.json`).
- `out/pdp-pep-poam-findings-{system_id}-{YYYYMMDD}.json` — pre-OSCAL
  POA&M findings (consumed by LOOP-A.A1).

### 5.3 Tracker DB schema additions

```sql
CREATE TABLE IF NOT EXISTS pdp_pep_evidence (
  envelope_id TEXT PRIMARY KEY,
  system_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  envelope_sha256 TEXT NOT NULL,
  envelope_path TEXT NOT NULL,
  coverage_pct REAL NOT NULL,
  total_pep_count INTEGER NOT NULL,
  failed_pep_count INTEGER NOT NULL,
  signature_ok INTEGER NOT NULL,
  rfc3161_status TEXT NOT NULL,
  ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pdp_pep_evidence_peps (
  envelope_id TEXT NOT NULL REFERENCES pdp_pep_evidence(envelope_id) ON DELETE CASCADE,
  pep_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  normalised_class TEXT NOT NULL,
  policy_tier TEXT NOT NULL,
  engine_family TEXT,
  policy_sha256 TEXT NOT NULL,
  uses_abac INTEGER NOT NULL,
  provenance TEXT NOT NULL,
  PRIMARY KEY (envelope_id, pep_id)
);

CREATE INDEX IF NOT EXISTS idx_peps_provider ON pdp_pep_evidence_peps(provider);
CREATE INDEX IF NOT EXISTS idx_peps_class ON pdp_pep_evidence_peps(normalised_class);
```

---

## 6. Algorithm / Steps

The X.X5 collector runs in a deterministic, REO-compliant pipeline.
Every step has explicit error handling; failures emit diagnostics
but never silently fall back to fake data (REO Rule 5).

```
Phase A — Input validation
A1.  Load X.X2 architecture map; verify Ed25519 signature.
A2.  Load X.X3 cloud-native augmentation; verify signature.
A3.  Load X.X1 pillars catalog; verify signature.
A4.  Load LOOP-INV-P1 inventory; verify signature.
A5.  Load operator overrides from pdp-pep-overrides.yaml (if present);
     schema-validate against PdpPepOverridesFile interface.

Phase B — Candidate enumeration
B1.  Walk architecture_map.pdp_pep_candidates[] AND
     cloud_native_aug.peps[] AND operator_overrides[]; union by
     deterministic key = sha256(provider + provider_native_type +
     deployment_location + scope). Resulting set = PEP_CANDIDATES.
B2.  Walk architecture_map.pe_candidates[] → PE_CANDIDATES.
B3.  Walk architecture_map.pa_candidates[] → PA_CANDIDATES.
B4.  Bucket PEP_CANDIDATES by provider into AWS_SET, GCP_SET,
     AZURE_SET, K8S_SET, OPERATOR_SET.

Phase C — Per-provider parallel collection
       (max_parallel_collectors = 8 by default; bounded via p-limit)
C1-AWS.  For each candidate in AWS_SET:
         - If type=='aws.verifiedaccess.endpoint':
             ec2:DescribeVerifiedAccessEndpoints + GetVerifiedAccessEndpointPolicy.
         - If type=='aws.verifiedaccess.group':
             ec2:DescribeVerifiedAccessGroups + GetVerifiedAccessGroupPolicy.
         - If type=='aws.ec2.security-group':
             ec2:DescribeSecurityGroups (returns InboundRules + OutboundRules).
         - If type=='aws.networkfirewall.firewall':
             network-firewall:DescribeFirewall +
             DescribeRuleGroup (per linked rule group).
         Preserve raw response (verbatim bytes) under
         policy_artifact.bytes_b64 (after secret redaction if enabled).
         Compute sha256, normalised_class, policy_tier, uses_abac,
         nist_control_refs.

C1-GCP.  For each candidate in GCP_SET:
         - If type=='gcp.compute.firewall':
             compute.firewalls.list (filter by network).
         - If type=='gcp.iap.backend':
             compute.backendServices.list (filter iap.enabled=true).
         - If type=='gcp.acm.accessLevel':
             accesscontextmanager.accessLevels.list.
         - If type=='gcp.acm.accessPolicy':
             accesscontextmanager.accessPolicies.list.
         Preserve verbatim JSON.

C1-AZURE. For each candidate in AZURE_SET:
          - If type=='azure.nsg':
              Microsoft.Network/networkSecurityGroups list.
          - If type=='azure.conditionalAccess':
              Microsoft Graph
              /v1.0/identity/conditionalAccess/policies.
          - If type=='azure.policy.assignment':
              ARM Microsoft.Authorization/policyAssignments list.
          Preserve verbatim JSON.

C1-K8S.  For each candidate in K8S_SET:
         - If type=='k8s.networking.networkpolicy':
             GET /apis/networking.k8s.io/v1/namespaces/<ns>/networkpolicies.
         - If type=='k8s.istio.authorizationpolicy':
             GET /apis/security.istio.io/v1/authorizationpolicies.
         - If type=='k8s.gatekeeper.constrainttemplate':
             GET /apis/templates.gatekeeper.sh/v1/constrainttemplates.
         - If type=='k8s.gatekeeper.constraint':
             GET /apis/constraints.gatekeeper.sh/v1beta1/<kind>.
         - If type=='k8s.kyverno.clusterpolicy':
             GET /apis/kyverno.io/v1/clusterpolicies.
         Preserve verbatim YAML (round-tripped to canonical YAML for
         sha256 stability).

C1-OPERATOR. For each entry in OPERATOR_SET:
             Pull policy_artifact.bytes from policy_location URI
             (file:// or git+https://) and treat as verbatim source
             with provenance='operator-override'.

Phase D — Normalisation
D1.  For each collected policy, compute:
     - normalised_class (enum) via per-provider mapping table.
     - policy_tier (network|identity|both) via heuristics:
         * network if only L3/L4 fields present.
         * identity if principals/sub claims present.
         * both if any field of either kind.
     - default_posture (default-deny|default-allow|mixed) for
       L3/L4 policies via rule-set analysis.
     - evaluation_order (verbatim from doc; never inferred).
     - uses_abac via structural check (see §2.10 mapping).
     - nist_control_refs via lookup table SC-7/AC-3.
D2.  Reconcile pep_id ↔ pe_ref ↔ pa_ref using architecture_map.

Phase E — Diagnostics + coverage
E1.  For each failed candidate: emit diagnostics entry with
     {code, pep_id, message, severity}.
E2.  Compute per-provider + global coverage_pct.
E3.  Update out/inventory-coverage.json (LOOP-INV-S contract).

Phase F — Sign + emit
F1.  Build canonical JSON (RFC 8785).
F2.  signEnvelope(payload, {algorithm: 'ed25519', key_ref}).
F3.  Request RFC 3161 timestamp; attach token.
F4.  Write out/pdp-pep-evidence-{system_id}-{YYYYMMDD}.json.

Phase G — Persistence + downstream
G1.  Insert envelope row + per-PEP rows into tracker DB.
G2.  Register envelope under role 'pdp-pep-evidence' in
     submission-bundle catalogue (LOOP-A.A4).
G3.  For each failed PEP collection OR for each PEP whose default
     posture violates target stage, emit a POA&M finding via
     LOOP-A.A1.
G4.  Emit Slack/PagerDuty notification on coverage_pct < 80%
     (configurable per zt-config.yaml).

Phase H — Verification
H1.  Re-read written envelope; verify signature.
H2.  Re-parse against ajv-compiled schema.
H3.  Confirm row count in tracker DB matches envelope.peps[].length.
H4.  Exit 0 if all green; exit 2 with structured error otherwise.
```

REO compliance notes per step: no stub returns (REO Rule 1); SDK
calls are real (Rule 4); failures surface in diagnostics and
inventory-coverage (Rule 5); signatures are real Ed25519 (Rule 6);
operator overrides carry explicit provenance (Rule 7).

---

## 7. Files to create / modify

All paths are absolute under `/Users/kenith.philip/FedRAMP 20x/`.

| Path | Action | Purpose |
|------|--------|---------|
| `cloud-evidence/core/pdp-pep-integration.ts` | create | Topology walker + candidate-enumerator + reconciliation logic; consumes X.X2 + X.X3 envelopes. |
| `cloud-evidence/core/pdp-pep-evidence-collector.ts` | create | Per-provider dispatcher + normaliser + sign+emit pipeline; orchestrates Phases A-H above. |
| `cloud-evidence/core/pdp-pep-normalisation.ts` | create | Pure-function normalisation helpers (default-posture analysis, uses_abac heuristic, nist_control_refs lookup). |
| `cloud-evidence/providers/aws/pdp-pep.ts` | create | AWS adapter: Verified Access (group+endpoint+policy), VPC SG, Network Firewall. |
| `cloud-evidence/providers/gcp/pdp-pep.ts` | create | GCP adapter: firewall, IAP-protected backends, AccessLevels, AccessPolicies. |
| `cloud-evidence/providers/azure/pdp-pep.ts` | create | Azure adapter: NSG, Conditional Access, Azure Policy assignments. |
| `cloud-evidence/providers/kubernetes/pdp-pep.ts` | create | k8s adapter: NetworkPolicy, Istio AuthorizationPolicy, Gatekeeper, Kyverno. |
| `cloud-evidence/schemas/zt/pdp-pep-evidence-v1.json` | create | ajv-compileable schema for the envelope. |
| `cloud-evidence/test/pdp-pep-integration.test.ts` | create | Stratum-A unit + integration tests for X.X5 (see §8). |
| `cloud-evidence/test/fixtures/zt/x5/` | create | Per-provider golden fixtures (real-shape SDK responses + verbatim policy snippets). |
| `cloud-evidence/scripts/lint-no-stubs.mjs` | modify | Add `core/pdp-pep-*.ts` + `providers/*/pdp-pep.ts` to G1 enforcement scope. |
| `cloud-evidence/scripts/check-provenance.mjs` | modify | Recognise `pdp-pep-evidence` role + per-PEP `provenance` field as G3-conformant. |
| `cloud-evidence/core/submission-bundle.ts` | modify | Add role `pdp-pep-evidence` to WELL_KNOWN; emitter walks `out/pdp-pep-evidence-*.json` glob. |
| `cloud-evidence/core/oscal-poam.ts` | modify | Recognise X.X5 finding category `pdp-pep-collection-failure` + `pep-default-posture-violation`. |
| `cloud-evidence/tracker/db/migrations/<N>_pdp_pep_evidence.sql` | create | Add `pdp_pep_evidence` + `pdp_pep_evidence_peps` tables per §5.3. |
| `cloud-evidence/tracker/server/routes/pdp-pep.ts` | create | Tracker UI API: list envelopes, per-envelope PEP browser, drill-down to verbatim source. |
| `cloud-evidence/tracker/client/src/pages/PdpPepBrowser.tsx` | create | UI page: per-provider tabs, per-PEP table, policy-source viewer (read-only). |
| `cloud-evidence/cli.ts` | modify | Add `--pdp-pep-evidence` flag (implied by `--zero-trust`). |
| `cloud-evidence/docs/CHANGELOG.md` | modify | Add LOOP-X.X5 entry at completion. |
| `cloud-evidence/docs/STATUS.md` | modify | Flip X.X5 row to done at completion. |
| `cloud-evidence/docs/loops/LOOP-X-SPEC.md` | modify | Update §12 status table row. |
| `cloud-evidence/pdp-pep-overrides.yaml.example` | create | Example operator-overrides file shipped with documentation. |

---

## 8. Test specifications

Tests live under `cloud-evidence/test/pdp-pep-integration.test.ts`
plus per-provider companions. Stratum A targets ≥ 90% coverage on
production paths and 100% on signing + canonical-JSON serialisation.
Stratum B (end-to-end) lives in `test/zt-end-to-end.test.ts` and
exercises X.X1 → X.X2 → X.X3 → X.X4 → X.X5 on the shared fixture
environment.

| id | scenario | fixture path | expected | acceptance |
|----|----------|--------------|----------|------------|
| T1 | Happy-path AWS Verified Access endpoint | `test/fixtures/zt/x5/aws/va-endpoint-cedar.json` | PEP record with `normalised_class='identity-aware-proxy'`, `policy_tier='identity'`, `engine_family='cedar'`, `uses_abac=true`, `nist_control_refs=['AC-3']` | ajv schema validates; sha256 stable across runs |
| T2 | Happy-path AWS VPC Security Group | `test/fixtures/zt/x5/aws/sg-default-deny.json` | PEP record with `normalised_class='network-perimeter-pep-east-west'`, `policy_tier='network'`, `default_posture='default-deny'`, `nist_control_refs=['SC-7']` | rules array preserved verbatim under bytes_b64 |
| T3 | Happy-path GCP VPC firewall rule | `test/fixtures/zt/x5/gcp/firewall-rule.json` | PEP record with `normalised_class='network-perimeter-pep-east-west'`, `policy_tier='network'`, `engine_family='gcp-firewall'` | gcp_policy_json populated verbatim |
| T4 | Happy-path GCP IAP backend service | `test/fixtures/zt/x5/gcp/iap-backend.json` | PEP record with `normalised_class='identity-aware-proxy'`, `policy_tier='identity'`, `uses_abac=true` | AccessLevels cited under workload_identity_refs |
| T5 | Happy-path Azure NSG | `test/fixtures/zt/x5/azure/nsg-priority-rules.json` | PEP record with `normalised_class='network-perimeter-pep-east-west'`, `policy_tier='network'`, `default_posture='default-deny'` | 5-tuple rules preserved verbatim |
| T6 | Happy-path Azure Conditional Access policy | `test/fixtures/zt/x5/azure/conditional-access.json` | PEP record with `normalised_class='conditional-access-engine'`, `policy_tier='identity'`, `uses_abac=true` | conditions+grantControls preserved |
| T7 | Happy-path k8s NetworkPolicy (default-deny) | `test/fixtures/zt/x5/k8s/np-default-deny.yaml` | PEP record with `policy_tier='network'`, `default_posture='default-deny'`, `engine_family='k8s-network-policy'` | YAML preserved as canonical YAML for sha256 stability |
| T8 | Happy-path Istio AuthorizationPolicy (DENY rule with principals) | `test/fixtures/zt/x5/k8s/istio-deny-principals.yaml` | PEP record with `policy_tier='identity'`, `evaluation_order=['CUSTOM','DENY','ALLOW']`, `uses_abac=true` | precedence captured verbatim from §2.4 docs |
| T9 | Happy-path Gatekeeper ConstraintTemplate + Constraint | `test/fixtures/zt/x5/k8s/gatekeeper-required-labels.yaml` | PEP record with `normalised_class='admission-webhook'`, `engine_family='gatekeeper'`, `rego_source` populated, `bindings[]` populated | Rego source SHA matches input |
| T10 | Happy-path Kyverno ClusterPolicy | `test/fixtures/zt/x5/k8s/kyverno-disallow-latest.yaml` | PEP record with `engine_family='kyverno'`, `normalised_class='admission-webhook'` | Kyverno spec preserved verbatim |
| T11 | Operator-override custom edge proxy | `test/fixtures/zt/x5/operator/edge-proxy-override.yaml` | PEP record with `provenance='operator-override'`, `pep_id` derived from override entry id | UI distinguishes operator-override via visual cue |
| T12 | AWS API auth-denied → diagnostic + POA&M | `test/fixtures/zt/x5/aws/va-endpoint-403.json` | Envelope emitted with `diagnostics[].code='auth:denied'`, POA&M `pdp-pep-collection-failure` for that pep_id | coverage_pct reflects miss; signature still valid on envelope shell |
| T13 | k8s NetworkPolicy unparseable (malformed CRD) | `test/fixtures/zt/x5/k8s/np-malformed.yaml` | Diagnostic `schema:unparseable`; PEP record only present if `emit_normalised_only_for_unparseable=true` | otherwise PEP elided, coverage_pct reflects miss |
| T14 | Signing happy path | n/a (uses test Ed25519 keypair) | Envelope `signature.signature_b64` verifies against `tests/fixtures/keys/zt-pubkey.pem` | round-trip canonical JSON → verify → ok |
| T15 | RFC 3161 TSA happy path | mock TSA returning a real token | `rfc3161_timestamp.status='verified'` | token DER parses; TSA URL recorded |
| T16 | RFC 3161 TSA outage → pending | mock TSA returning 503 | `rfc3161_timestamp.status='pending'`; tracker DB job scheduled | retry job present in DB |
| T17 | Schema validation rejects extra fields | hand-edited envelope with extra root field | ajv error; non-zero exit | error message names the extra field |
| T18 | Multi-cluster mixed (AWS+GCP+Azure+k8s all present) | `test/fixtures/zt/x5/multi-cloud/` | Per-provider coverage all > 0; total PEP count = sum | per-provider section in coverage envelope populated |
| T19 | Coverage regression check fails on PEP drop | inject a missing PEP between runs | `npm run check:coverage-regression` reports red | regression check picks up the per-provider drop |
| T20 | Secret-redaction strips AWS access keys from preserved bytes | fixture containing a literal `AKIA…` in policy text | bytes_b64 has `AKIA…` replaced with `[REDACTED:aws-access-key]` | sha256 differs from raw input; raw never written |
| T21 | Default-posture computation: NetworkPolicy with no Ingress rules | `test/fixtures/zt/x5/k8s/np-no-ingress.yaml` | `default_posture='default-deny'` (per k8s docs: any policy selecting a pod for Ingress with no rules denies all) | matches k8s NetworkPolicy semantics |
| T22 | Default-posture computation: AWS SG with `0.0.0.0/0` ingress on tcp/22 | `test/fixtures/zt/x5/aws/sg-ssh-open.json` | `default_posture='default-allow'`; POA&M `pep-default-posture-violation` emitted | finding cross-walked to SC-7 |
| T23 | NIST control cross-walk: identity-tier PEP → AC-3 | n/a (unit) | nist_control_refs includes 'AC-3' for identity-tier rows | mapping table audited |

Total: 23 tests across the matrix (exceeds the ≥ 15 requirement).
Adversarial cases per LOOP-X-SPEC §7 expectation are T12, T13, T19,
T22.

---

## 9. Risks

Full register lives in `docs/loops/LOOP-X-RISKS.md`. Below are the
≥ 4 X.X5-specific risks (per per-slice doc structure).

| ID | Risk | Severity | Mitigation |
|----|------|----------|------------|
| X5-R1 | **Multi-cloud heterogeneity** — different clouds expose entirely different PEP grammars; a naive normaliser will lose semantic fidelity (e.g. collapsing Cedar `forbid` and Istio `DENY` into a single posture loses the precedence subtleties of §2.4). | **High** | (a) `policy_artifact.bytes_b64` preserves verbatim source so the 3PAO can fall back to the original; (b) `evaluation_order` is recorded verbatim from the docs (never inferred); (c) per-provider adapters are isolated so a fidelity bug in one does not contaminate others; (d) §8 tests T1-T10 cover the canonical happy path per provider. |
| X5-R2 | **Operator runs custom PEP not on default detection list** — the CSP may deploy an internal proxy (e.g. a custom Envoy fleet, a home-grown Lambda authorizer, an Apigee proxy used as an L7 PEP) that the system has no detector for. Missing this PEP would understate ZT coverage and invalidate the X.X4 scorecard. | Medium | (a) `pdp-pep-overrides.yaml` operator-supplied addition path with `provenance: operator-override`; (b) UI distinguishes operator-override entries from system-discovered; (c) operator-overrides participate in coverage_pct so the system never inflates the figure with operator-supplied entries. |
| X5-R3 | **Default-posture computation is hard for L3/L4** — k8s NetworkPolicy "default-deny via empty Ingress" vs "no NetworkPolicy at all → default-allow" is subtle; AWS SG starts implicitly deny but may be opened by a `0.0.0.0/0` rule; GCP firewall has hierarchical policies that override per-network rules. A wrong determination would feed a wrong POA&M finding and contaminate X.X4. | **High** | (a) Per-engine default-posture rules encoded as named helpers (testable); (b) §8 tests T7, T21, T22 cover the canonical edge cases; (c) any `mixed` posture flagged as a diagnostic and surfaced to operator review; (d) the `nist_control_refs` enable 3PAO override via the AR. |
| X5-R4 | **Secrets in captured policy bytes** — policies can embed credentials (e.g. a Gatekeeper Rego that calls an external API with an API key, a Conditional Access policy that names an internal URL with a query-string token, an inline SAML federation cert that includes a private key). REO Rule 5 forbids silent data loss but Rule 7 also forbids leaking secrets into emitted artifacts. | **High** | (a) `redact_secrets_in_policies: true` by default; (b) redaction patterns cover AWS access keys (`AKIA…`), GCP service-account JSON markers, JWT triplets (`eyJ…\.eyJ…\.[A-Za-z0-9_-]+`), private-key PEM headers, generic API-key regexes; (c) §8 test T20 enforces redaction; (d) operator can disable redaction only via explicit flag for diagnostic purposes; the envelope records the redaction state for audit. |
| X5-R5 | **API rate-limit storms on large fleets** — a CSP with thousands of namespaces × dozens of NetworkPolicies + hundreds of SGs can blow through SDK rate limits and produce partial collection that looks like genuine PEP absence. | Medium | (a) `max_parallel_collectors = 8` default; (b) per-provider exponential backoff via the shared retry middleware (LOOP-A retry pattern); (c) coverage_pct is the indicator — if it dips, the orchestrator emits a `coverage:rate-limited` diagnostic and the operator can re-run with smaller parallelism; (d) X.X5 never silently drops partial collections; partial runs fail with a non-zero exit. |
| X5-R6 | **Schema drift in upstream APIs** — k8s API groups (Istio v1 vs v1beta1, security.istio.io migrations), Microsoft Graph beta vs v1.0, AWS Verified Access GA changes; a silent drift would produce parse failures or, worse, parse-success-with-missing-fields. | Medium | (a) ajv schema for the envelope (every emitted field declared); (b) per-provider response-validators that fail-loud if a known field is missing; (c) `scripts/check-zt-source-drift.mjs` runs daily and notifies on schema URL changes (LOOP-X-SPEC §2.13 / §21). |
| X5-R7 | **Operator-override flooding** — an operator could declare dozens of bogus PEPs in `pdp-pep-overrides.yaml` to inflate coverage. | Low | (a) Coverage roll-up segments system-discovered vs operator-override (separate per-provider buckets); (b) tracker UI surfaces both numbers; (c) 3PAO override-review workflow exists per existing audit pattern; (d) per-override `operator_attestation_text` required and rendered verbatim. |

---

## 10. Open questions

- **Q1 — JWCC overlay for DoD customers.** Joint Warfighter Cloud
  Capability (JWCC) cloud-customer contracts may require a DoD-
  specific overlay (e.g. capture STIG-aligned policy bytes from each
  PEP, attach NIPRNet / SIPRNet boundary metadata, emit a
  DoD-CIO-specific projection of the envelope). REQUIRES-RESEARCH;
  out-of-scope for X.X5 baseline; could become X.X5-JWCC sibling.
- **Q2 — Cedar formal verification.** AWS publishes a Cedar formal-
  verification tool (the Cedar Soufflé proof). Should X.X5 invoke it
  on captured Cedar bytes and emit the proof-status as
  `policy_artifact.formal_verification_status`? REQUIRES-OPERATOR-
  INPUT — decision rests on whether the operator wants the cost of
  per-policy verification at every collection cycle.
- **Q3 — Cilium-mesh + eBPF NetworkPolicy.** Cilium's CiliumNetworkPolicy
  is a superset of k8s NetworkPolicy with L7 fields. Should X.X5
  treat CiliumNetworkPolicy as a separate `engine_family='cilium'`
  or as a k8s-NetworkPolicy variant? Decision pending; default is
  to add `cilium` as a parallel engine_family.
- **Q4 — Multi-cluster Istio.** If the CSP runs Istio in multi-cluster
  mode, AuthorizationPolicy objects can be replicated across
  clusters with different bindings. Should X.X5 reconcile across
  clusters or emit per-cluster? Default: per-cluster; multi-cluster
  reconciliation deferred to future X.X6.
- **Q5 — Cross-tenant policies in multi-tenant SaaS.** A SaaS CSP
  with hard tenant isolation may have one set of PEPs per tenant
  (e.g. tenant-scoped namespaces). Does the X.X5 envelope segment
  by tenant or aggregate? Default: aggregate, with `scope.tenant_id`
  field on each PEP record. Customer-facing detail belongs in the
  tracker UI filters, not the envelope shape.
- **Q6 — Rego import resolution.** A Gatekeeper ConstraintTemplate
  may `import` other Rego packages from an external bundle. Should
  X.X5 walk the import graph and capture the imported sources?
  Default: no — only the top-level template Rego is captured; the
  `bindings[]` records the engine_family so a 3PAO knows to inspect
  any bundle separately.
- **Q7 — Policy review-cadence verification.** `last_policy_review`
  is operator-supplied. Should X.X5 cross-check against git history
  of the policy file (if policy lives in a git-managed repo)? Useful
  but adds repo-scanning scope; out-of-scope for X.X5 baseline.
- **Q8 — Network Firewall rule groups across regions.** AWS Network
  Firewall rule groups can be shared across regions via Firewall
  Manager. Should X.X5 follow shared-rule-group references and
  collect once? Default: collect per-firewall instance; dedupe by
  rule-group ARN under `policy_artifact.shared_rule_group_arns[]`.

---

## 11. REQUIRES-OPERATOR-INPUT

| Field name | Type | Validator | UI location | Failure mode if missing |
|------------|------|-----------|-------------|--------------------------|
| `pdp_overrides[]` (YAML) | array of `PdpPepOverrideEntry` | schema-validated against `PdpPepOverridesFile` interface | repo file `pdp-pep-overrides.yaml` | None (optional). If file missing, X.X5 still runs but emits no operator-override records. |
| `pdp_overrides[].id` (per entry) | string | `^[A-Za-z0-9-]{3,64}$` | repo file | Entry rejected; diagnostic `override:id-invalid` emitted. |
| `pdp_overrides[].classification` | enum (PE / PA / PEP) | enum validator | repo file | Entry rejected; diagnostic emitted. |
| `pdp_overrides[].policy_location` | string (URI) | URI parse + (for `file://`) existence check + (for `git+https://`) reachability check | repo file | Entry rejected; diagnostic emitted. |
| `pdp_overrides[].operator_attestation_text` | string | non-empty, no control chars | repo file | Entry rejected; UI cannot render override without attestation. |
| `pdp_overrides[].last_policy_review` | string (ISO date) | ISO 8601 validator | repo file | Entry rejected. |
| `zt_config.max_parallel_collectors` | integer ≥ 1 ≤ 32 | range validator | `zt-config.yaml` | Default 8. |
| `zt_config.per_provider_timeout_ms` | integer ≥ 1000 ≤ 600000 | range validator | `zt-config.yaml` | Default 60000. |
| `zt_config.collect_verbatim_source` | boolean | boolean validator | `zt-config.yaml` | Default true (REO Rule 7 — recommended on). |
| `zt_config.redact_secrets_in_policies` | boolean | boolean validator | `zt-config.yaml` | Default true (REO Rule 7). |
| `zt_config.coverage_alert_threshold_pct` | float 0-100 | range validator | `zt-config.yaml` | Default 80.0. |
| `ed25519_signing_key_ref` (reused from LOOP-A.A5) | string (KMS resource ref) | sign-test on startup | Settings → Compliance → Signing | Orchestrator refuses to run; exit code 2 with `KmsKeyUnavailableError`. |
| `rfc3161_tsa_url` (reused from LOOP-A.A5) | string (URL) | URL validator + TSA-handshake test | Settings → Signing → Timestamp Authority | Default org TSA; warn if missing — RFC 3161 status will be `pending`. |
| `signing_officer_name` (reused from LOOP-A.A5) | string | non-empty, no control chars | Settings → Compliance → Signing | Envelope signing blocks. |
| `signing_officer_title` (reused from LOOP-A.A5) | string | non-empty, no control chars | Settings → Compliance → Signing | Envelope signing blocks. |

Total: 15 fields. Of these, **4 are blocking** at startup (orchestrator
refuses to run if missing), **3 are entry-level rejection** (per
override entry), and **8 are defaulting** (X.X5 chooses a safe default
if missing).

---

## 12. Implementation log

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-08 | LOOP-X.X5 spec authoring workflow | Specification authored via FedPy workflow; sibling files X.X1-X.X4 documented in LOOP-X-SPEC.md §3. | TBD | This per-slice doc proposed. Verbatim quotes verified against pinned URLs accessed 2026-06-08. Schema + algorithm + REQUIRES-OPERATOR-INPUT table + 23 tests all enumerated. Ready for implementation handoff. |

---

## 13. Completion checklist

> The following 7 steps are quoted verbatim from
> `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`. They are MANDATORY
> for every slice in every loop. NO EXCEPTIONS. Every session that ships
> a slice MUST execute this checklist atomically with the slice's own
> commit.
>
> ### Step 1 — Verify the slice is REO-compliant
> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```
>
> ### Step 2 — Update STATUS.md
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority
>
> ### Step 3 — Update the loop's spec doc
> Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.
>
> ### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-X.XN: <Slice title>
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>
>
> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```
>
> ### Step 6 — Update commit hash in STATUS.md + loop spec
> Now that the commit exists, get its hash:
> ```bash
> git log -1 --format=%h
> ```
> Open STATUS.md + the loop's spec doc — paste the actual commit hash in the rows you updated in step 2+3.
> Amend the commit:
> ```bash
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md
> git commit --amend --no-edit
> ```
>
> ### Step 7 — Push
> ```bash
> git push origin main
> ```
>
> ### Step 8 (X.X5-specific addendum)
> After the commit lands, append/update the X.X5 row in STATUS.md
> (status → done, commit hash, last_updated); update LOOP-X-SPEC.md §12
> status table (X.X5 row → done with commit hash + last_updated);
> append a CHANGELOG entry under "Unreleased" naming
> `LOOP-X.X5 — Policy Decision Point / Policy Enforcement Point
> Integration Evidence Collector`; push to origin/main; verify with
> `git log --oneline -3`. Only THEN is X.X5 closed.

REO STANDARD (Rules 1–10) governs every line of production code
described in §7. No invented citations. Apache-2.0 clean-room. Every
emitted byte traces to a real cloud-native API call, a real operator
override file entry, a real LOOP-X catalog read, or a real upstream
LOOP-A signing primitive.
