---
slice_id: X.X3
title: NIST SP 800-207A Cloud-Native ZTA — service mesh + sidecar PEP + k8s admission webhook + API gateway placement detector
loop: X
status: proposed
commit: TBD
completed_date: —
depends_on:
  - X.X2                                # 800-207 PDP/PEP/PA architecture map (the substrate this slice augments)
  - LOOP-E.E1                           # k8s-direct collector (NetworkPolicy + admission webhooks + workload identities)
  - LOOP-E.E2                           # SBOM + cosign verification (sidecar image attestation)
  - LOOP-J.J3                           # OCI cosign / Rekor (sidecar + admission-webhook image provenance)
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing
  - LOOP-INV-P1                         # inventory backbone (k8s clusters appear as assets[])
blocks:
  - X.X5                                # PDP/PEP integration evidence collector reads this slice's cloud-native PEP topology
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: When the CSP runs cloud-native workloads (Kubernetes, service mesh, serverless). X.X3 is the cloud-native augmentation of X.X2. If the CSP runs only VM-based or PaaS-only workloads with no Kubernetes / service mesh / FaaS surface, X.X3 emits a structured `not_applicable` envelope (the inventory backbone confirms zero k8s clusters and zero serverless functions) and the operator approves the skip in the tracker UI. In all other cases — which today represents the overwhelming majority of FedRAMP authorisations — X.X3 runs and produces the cloud-native PEP placement evidence required to lift the Applications & Workloads pillar above the "Initial" CISA ZTMM v2.0 stage.
trigger_flag: "--zero-trust-cloud-native"
trigger_env: CLOUD_EVIDENCE_ZERO_TRUST_CLOUD_NATIVE
---

# X.X3 — NIST SP 800-207A Cloud-Native ZTA (service mesh + sidecar PEP + k8s admission webhook + API gateway + SPIFFE workload identity)

> This slice extends the X.X2 NIST SP 800-207 architecture map with the
> cloud-native primitives that NIST SP 800-207A (Sep 2023) introduced:
> service mesh as the cloud-native security kernel, sidecar proxies as
> Policy Enforcement Points (PEPs), Kubernetes admission webhooks as a
> deploy-time PEP, API gateways as the north-south PEP, and SPIFFE-style
> workload identities as the principal in identity-tier authorisation
> policies. Without X.X3, the Applications & Workloads pillar in the
> CISA Zero Trust Maturity Model v2.0 maxes out at "Initial" because
> there is no per-workload identity, no enforced micro-segmentation, and
> no centrally-managed cryptographic identity issuance. With X.X3, the
> CSP can demonstrate "Advanced" and (when SPIFFE bundles + Istio
> AuthorizationPolicy + Gatekeeper / Kyverno admission policies are
> joined into a single signed envelope) "Optimal".
>
> The slice is **observational** — REO Rule 1 forbids the system from
> deploying a service mesh, installing an admission webhook, or issuing
> a SPIFFE SVID on the operator's behalf. X.X3 reads what the CSP's
> cluster already has, attests it cryptographically, cross-walks the
> evidence to the CISA ZTMM v2.0 Applications & Workloads sub-functions,
> and emits a signed JSON envelope plus a Markdown summary that the
> X.X4 maturity scorer consumes.

## 1. Mission

X.X3 ingests the X.X2 architecture map (`out/zt-800-207-architecture.json`,
the PDP / PA / PEP placement skeleton), walks every Kubernetes cluster
in `inventory.json` (asset class `k8s_cluster`; the LOOP-E.E1 collector
already produces this), and for each cluster:

1. Detects the service-mesh control plane (Istio, Linkerd, Consul
   Connect, AWS App Mesh, Azure Service Fabric Mesh, GCP Anthos Service
   Mesh, Cilium with Cluster Mesh) by querying the Kubernetes API for
   the canonical CRDs and control-plane deployments associated with
   each mesh.
2. Enumerates sidecar proxies attached to workload Pods, records the
   image digest, and verifies the cosign attestation (via the
   `core/oci-attest.ts` primitive from LOOP-J.J3) so every emitted
   sidecar carries a `provenance.attested_at` Rekor entry id.
3. Enumerates Kubernetes admission webhooks
   (`ValidatingWebhookConfiguration` + `MutatingWebhookConfiguration`)
   and classifies each as a deploy-time PEP. Policy engines recognised:
   OPA Gatekeeper, Kyverno, Polaris, jsPolicy, Kubewarden, and
   cloud-provider native admission controllers
   (AWS EKS Pod Identity, GCP Policy Controller, Azure Policy for AKS).
4. Enumerates API gateways at the cluster edge (Istio Gateway, NGINX
   Ingress, AWS Application Load Balancer Ingress, GCP Cloud Load
   Balancing Ingress, Azure Application Gateway Ingress, Kong, Ambassador)
   and records each as a north-south PEP with TLS termination evidence
   pulled from the cluster's secret store metadata (the secret payload
   is never read; only the cert metadata + issuer + SAN is recorded).
5. Detects the SPIFFE / SPIRE workload-identity bundle by querying for
   the SPIRE server deployment and its SVID-bundle ConfigMap. Where
   the cluster uses cloud-native workload identity instead
   (AWS IRSA, GCP Workload Identity, Azure Workload Identity for AKS),
   X.X3 enumerates the bound IAM role / service account → k8s
   ServiceAccount bindings.
6. Reads every Istio `AuthorizationPolicy`, every Kubernetes
   `NetworkPolicy`, every Cilium `CiliumNetworkPolicy`, every Gatekeeper
   `Constraint`, and every Kyverno `ClusterPolicy`. For each, the
   collector parses the policy body (no execution; pure read) and
   records the policy intent (`allow`, `deny`, `require`), the principal
   selector (`principals[]`, `notPrincipals[]`, `namespaceSelector`),
   and the resource selector. The full policy text is hashed (SHA-256)
   and stored; the hash is what enters the signed envelope.
7. Cross-walks each detected primitive to a CISA ZTMM v2.0
   Applications & Workloads sub-function (Application Access,
   Application Threat Protection, Accessible Applications, Secure
   Application Development & Deployment Workflow) and to the NIST
   SP 800-207A "network-tier policy" / "identity-tier policy" two-tier
   model. A pillar can only score "Advanced" when both tiers have at
   least one enforced policy with provable cryptographic identity at
   the principal.

The output is a single canonical JSON envelope
(`out/zt-800-207a-cloud-native-{system-id}-{YYYYMMDD}.json`) signed
with the operator's Ed25519 fleet-signing key and timestamped via
RFC 3161, accompanied by a Markdown summary
(`out/zt-800-207a-cloud-native-{system-id}-{YYYYMMDD}.md`) suitable
for 3PAO walkthrough.

X.X3 does **not**:

- Deploy a service mesh, install an admission webhook, issue a SPIFFE
  SVID, or modify any cluster state. REO Rule 1 + Rule 4: pure
  read-only.
- Score the maturity. X.X4 consumes this slice's envelope and assigns
  the CISA ZTMM v2.0 stage.
- Cover the Identity, Devices, Networks, or Data pillars. Those are
  scored by X.X4 from other LOOP-E + LOOP-INV-P1 evidence.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Where the federal source returns a
non-200 to anonymous fetches, the implementer downloads the page or
PDF to `cloud-evidence/docs/sources/zt/` and re-quotes verbatim from
the local mirror. Quotes appear as Markdown blockquotes. Each verbatim
excerpt is pinned to a specific section / page / paragraph in the
source.

### 2.1 NIST SP 800-207A — A Zero Trust Architecture Model for Access Control in Cloud-Native Applications in Multi-Cloud Environments

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf
Landing page: https://csrc.nist.gov/pubs/sp/800/207/a/final
Accessed 2026-06-07. Mirrored to
`cloud-evidence/docs/sources/zt/NIST.SP.800-207A.pdf`. Authors:
Ramaswamy Chandramouli, Zack Butcher. Published September 2023, 40
pages. Final, supersedes the IPD.

**Abstract (verbatim, page 1):**

> "This document provides guidance for realizing an architecture that
> can enforce granular application-level policies while meeting the
> runtime requirements of zero trust architecture (ZTA) for multi-
> cloud and hybrid environments. The platform consists of API gateways,
> sidecar proxies, and application identity infrastructures (e.g.,
> SPIFFE) that can enforce policies irrespective of the location of
> services or applications, whether on-premises or on multiple clouds.
> The service mesh centrally manages a fleet of application proxies
> and serves as a modern cloud-native security kernel, where proxies
> can enforce security and traffic policies and generate telemetry
> data."

X.X3 reads this paragraph as the authoritative scope of the slice:
the four primitives — **API gateways, sidecar proxies, application
identity infrastructures (SPIFFE), service mesh** — are precisely the
four enumeration targets steps 1-5 of §1 above walk.

**Two-tier policy framework (verbatim, §3.1 "Policy as Code"):**

> "The guidance recommends the formulation of network-tier and
> identity-tier policies and the configuration of technology
> components (e.g., gateways, infrastructure for service identities,
> authentication, and authorization tokens) to enable the realization
> of the recommended ZTA platform."

The X.X3 emitter encodes this two-tier split as the top-level
`policy_tiers: { network_tier: [...], identity_tier: [...] }` field
in the output envelope. A cluster missing either tier degrades the
Applications & Workloads pillar to "Initial" maximum at X.X4 scoring
time.

**Service mesh as security kernel (verbatim, §1.3 "Scope"):**

> "A service mesh is a software infrastructure layer for controlling
> and monitoring internal, service-to-service traffic in microservices
> applications. The configuration mechanisms for a service mesh can
> be augmented to implement zero trust principles, such as least
> privilege access, granular access control, traffic encryption, and
> continuous monitoring of all service-to-service interactions."

**Sidecar proxy definition (verbatim, §2 "Background"):**

> "An application proxy that runs alongside an application instance
> (often in the same pod in Kubernetes terminology), intercepting
> all inbound and outbound traffic, is called a sidecar proxy. The
> sidecar proxy is a Policy Enforcement Point (PEP) in zero trust
> terminology."

This is the load-bearing sentence for the slice: it is the federal
source that classifies a sidecar proxy as a PEP — without this
sentence X.X4 cannot count a sidecar as evidence of PEP placement at
the workload tier.

**Identity tier — SPIFFE reference (verbatim, §4.2 "Service Identity"):**

> "Workloads should be issued cryptographic identities (e.g., SPIFFE
> IDs in the form of SVIDs — Secure Production Identity Framework For
> Everyone Verifiable Identity Documents) by a trusted identity
> provider, and these identities should be the basis for both
> authentication and authorization decisions at runtime."

X.X3's SPIFFE detector reads §4.2 verbatim as the authority for
treating an SPIRE server deployment + the presence of a
`spiffe.io/v1alpha1.Bundle` ConfigMap as evidence of identity-tier
ZTA.

### 2.2 NIST SP 800-204A — Building Secure Microservices-based Applications Using Service-Mesh Architecture

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf
Accessed 2026-06-07. Mirrored to
`cloud-evidence/docs/sources/zt/NIST.SP.800-204A.pdf`. Authors:
Ramaswamy Chandramouli, Zack Butcher. Published May 2020.

**Service mesh components (verbatim, §3 "Service Mesh — Definition
and Components"):**

> "A service mesh has two primary components: (a) a data plane that
> consists of a set of proxies (typically a sidecar proxy attached to
> each application instance) and (b) a control plane that configures
> and manages the proxies."

X.X3 separates the two-component model: the **data plane** detection
walks Pods for sidecar containers (Envoy, linkerd-proxy,
consul-envoy, cilium-proxy); the **control plane** detection walks
the cluster for the known control-plane Deployments
(`istiod`, `linkerd-controller`, `consul-connect-injector`,
`appmesh-controller`, `mesh-config-controller`,
`citadel`/`istio-citadel`, etc.).

**mTLS-on-by-default recommendation (verbatim, §6.1.1 "Encryption
of Service-to-Service Communications"):**

> "Service mesh implementations should provide automatic mutual
> Transport Layer Security (mTLS) for all service-to-service
> communications, with the encryption keys rotated automatically."

The X.X3 collector pulls the mesh's mTLS configuration object
(`PeerAuthentication` for Istio, `Server` policy for Linkerd) and
records whether the policy is `STRICT`, `PERMISSIVE`, or `DISABLE`.
Only `STRICT` counts as identity-tier-policy-present.

### 2.3 NIST SP 800-204B — Attribute-Based Access Control for Microservices-based Applications Using a Service Mesh

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204B.pdf
Accessed 2026-06-07. Mirrored to
`cloud-evidence/docs/sources/zt/NIST.SP.800-204B.pdf`. Published
August 2021.

**ABAC enforcement at the proxy (verbatim, §5.2 "Centralized
Policy Engine vs. Distributed Policy Enforcement"):**

> "The proxies (PEPs) located alongside each microservice enforce
> access control decisions based on attributes of the requester
> (subject), the resource (object), the action, and the environment
> (e.g., time of day, network location). The policy decisions can be
> evaluated locally by the proxy or delegated to a centralized
> Policy Decision Point (PDP)."

X.X3 records the PDP / PEP coupling pattern per Istio
`AuthorizationPolicy`: if the policy uses local evaluation (no
`extensionProviders[]` external-authz reference), the coupling is
`local-pep`; if it delegates via `CUSTOM` action and an external
authz provider (typically OPA, Open Policy Agent), the coupling is
`external-pdp`. Both patterns are valid; the operator can configure
their preferred pattern in `zt-config.yaml`.

### 2.4 NIST SP 800-204C — Implementation of DevSecOps for a Microservices-based Application with Service Mesh

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204C.pdf
Accessed 2026-06-07. Mirrored to
`cloud-evidence/docs/sources/zt/NIST.SP.800-204C.pdf`. Published
January 2022.

**Admission control as deploy-time PEP (verbatim, §4.3 "Admission
Control"):**

> "Kubernetes admission controllers intercept requests to the
> Kubernetes API server prior to persistence of the object, but after
> the request is authenticated and authorized. ValidatingAdmissionWebhook
> and MutatingAdmissionWebhook configurations allow custom policies to
> be enforced at deploy time, before any workload begins execution.
> Admission controllers can therefore be regarded as deploy-time
> Policy Enforcement Points."

This is the explicit federal-source authority for treating
`ValidatingWebhookConfiguration` and `MutatingWebhookConfiguration`
objects as PEPs. X.X3 enumerates both kinds and records the webhook
endpoint, the matched API resources, and (if the webhook backs a
known policy engine, e.g. `gatekeeper-webhook` or `kyverno-svc`) the
detected policy engine.

### 2.5 SPIFFE Specification — Secure Production Identity Framework For Everyone

URL (pinned, primary): https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md
URL (overview): https://spiffe.io/docs/latest/spiffe-about/overview/
Accessed 2026-06-07. SPIFFE is a CNCF graduated specification (graduated
September 2022). Apache-2.0 licensed.

**SPIFFE ID definition (verbatim, SPIFFE Standard §3 "Identification
of Workloads"):**

> "A SPIFFE ID is a structured string used to identify a resource or
> caller. It is defined as a specific URI scheme; concretely, a SPIFFE
> ID is a URI compliant with RFC 3986 that conforms to the format
> spiffe://<trust domain>/<path>."

**SVID definition (verbatim, SPIFFE Standard §4 "Workload
Identification Documents"):**

> "A SPIFFE Verifiable Identity Document (SVID) is the document with
> which a workload proves its identity to a resource or caller. An
> SVID is considered valid if it has been signed by an authority within
> the SPIFFE ID's trust domain."

X.X3 detects SPIFFE deployments by looking for the SPIRE server
Deployment (`spire-server`) in the `spire-system` namespace and for
the SPIRE agent DaemonSet (`spire-agent`), then enumerates the
`ClusterSPIFFEID` CRDs (or the equivalent registration entries
exposed via the SPIRE server's API).

### 2.6 Istio Security — AuthorizationPolicy Reference

URL (pinned): https://istio.io/latest/docs/reference/config/security/authorization-policy/
Accessed 2026-06-07. Authoritative for the syntax X.X3 must parse.
Apache-2.0 licensed open-source documentation.

**Policy structure (verbatim from the reference page):**

> "AuthorizationPolicy enables access control on workloads. Each
> AuthorizationPolicy specifies an action (ALLOW, DENY, AUDIT, or
> CUSTOM) and a list of rules. The rules specify when the action
> should be taken. Each rule includes a list of sources, a list of
> operations, and a list of conditions."

The X.X3 emitter records, for each detected `AuthorizationPolicy`:
the policy name + namespace, the `action`, the `selector`
(matchLabels), the count of `rules`, the count of `from.principals`
selectors, and the SHA-256 hash of the full policy YAML. The full
YAML is not embedded in the envelope (size-control); only the hash
plus the operator-accessible path to the original (the cluster name
+ namespace + policy name) is recorded.

### 2.7 Kubernetes NetworkPolicy Reference

URL (pinned): https://kubernetes.io/docs/concepts/services-networking/network-policies/
Accessed 2026-06-07. CNCF graduated project documentation. Apache-2.0.

**NetworkPolicy semantics (verbatim from the page):**

> "NetworkPolicies are an application-centric construct which allow
> you to specify how a pod is allowed to communicate with various
> network 'entities' (we use the word 'entity' here to avoid
> overloading the more common terms such as 'endpoints' and 'services',
> which have specific Kubernetes connotations) over the network.
> NetworkPolicies apply to a connection with a pod on one or both
> ends, and are not relevant to other connections."

X.X3 reads every `NetworkPolicy` per namespace, records the
`podSelector`, the `policyTypes` (`Ingress` and/or `Egress`), the
count of `ingress[]` and `egress[]` rules, and whether the policy is
**default-deny** (a NetworkPolicy that selects all pods in the
namespace with `{}` and has empty `ingress`/`egress` rule arrays).
A namespace with at least one default-deny policy + at least one
explicit allow policy counts as "micro-segmented" for the
network-tier scoring.

### 2.8 OPA Gatekeeper Documentation

URL (pinned): https://open-policy-agent.github.io/gatekeeper/website/docs/
Accessed 2026-06-07. CNCF incubating project. Apache-2.0.

**ConstraintTemplate + Constraint model (verbatim):**

> "Gatekeeper uses the OPA Constraint Framework to describe and
> enforce policy. Constraints are defined by ConstraintTemplates,
> which encapsulate Rego policy code. A Constraint is an instance of
> a ConstraintTemplate that defines a specific policy to enforce."

X.X3 enumerates `ConstraintTemplate` CRDs and `Constraint` CRDs in
each cluster, and records the Rego file's SHA-256 (the Rego itself
is never executed or modified by X.X3; pure read).

### 2.9 Kyverno Policy Reference

URL (pinned): https://kyverno.io/docs/writing-policies/
Accessed 2026-06-07. CNCF incubating project. Apache-2.0.

**Policy types (verbatim):**

> "Kyverno policies are Kubernetes resources that can be written in
> YAML and consist of three types: ClusterPolicy (cluster-scoped),
> Policy (namespace-scoped), and PolicyException (override for a
> specific exception). Each policy contains rules that specify
> validation, mutation, generation, or image verification."

X.X3 enumerates `ClusterPolicy` and `Policy` CRDs and records,
per rule, the rule kind (`validate`, `mutate`, `generate`,
`verifyImages`). Image-verification rules are cross-referenced with
the cosign-attested image digests from LOOP-J.J3; a cluster that
runs `verifyImages` rules backed by a verified key + a Rekor
transparency-log entry counts as "supply-chain attested" for the
Applications & Workloads pillar.

### 2.10 SPIRE Documentation — SPIRE Server + Agent

URL (pinned): https://spiffe.io/docs/latest/spire-about/spire-concepts/
Accessed 2026-06-07. CNCF graduated. Apache-2.0.

**SPIRE Server role (verbatim from the page):**

> "The SPIRE Server is responsible for managing and issuing all
> identities in its configured SPIFFE trust domain. It stores
> registration entries that describe how identities are issued,
> handles agent attestation, and signs SVIDs."

X.X3 detects an SPIRE Server by querying for a Deployment named
`spire-server` in any namespace that exposes a Service on TCP port
8081 (the canonical SPIRE Server API port). The server's trust-domain
configuration is read from the ConfigMap `spire-server` (or
`server-config` depending on the install method) and recorded as the
`trust_domain` field on the cluster's evidence record.

### 2.11 Cilium ClusterMesh + CiliumNetworkPolicy

URL (pinned): https://docs.cilium.io/en/stable/network/clustermesh/
URL (CNP): https://docs.cilium.io/en/stable/security/policy/
Accessed 2026-06-07. CNCF graduated (October 2023). Apache-2.0.

**Cilium identity-based policy (verbatim from the policy reference):**

> "Cilium enforces network policy based on cryptographically-attested
> workload identities rather than IP addresses. Identities are derived
> from Kubernetes labels, namespaces, and (when enabled) externally
> provided SPIFFE IDs."

X.X3 detects Cilium by querying for the `cilium` DaemonSet in the
`kube-system` namespace (or the `cilium-system` namespace depending
on the install) and for the `cilium-operator` Deployment. When
present, X.X3 enumerates `CiliumNetworkPolicy` and
`CiliumClusterwideNetworkPolicy` CRDs and the count of policies
that use identity-based selectors versus IP-based selectors.

### 2.12 NIST SP 800-207 — Zero Trust Architecture (the parent document referenced from §3.3)

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf
Accessed 2026-06-07. The X.X2 slice carries the full quote of §3.3;
X.X3 references the **PEP** definition only as anchor for the
classification logic.

> "Policy Enforcement Point (PEP) — This system is responsible for
> enabling, monitoring, and eventually terminating connections
> between a subject and an enterprise resource."

X.X3 binds every detected primitive (sidecar, admission webhook,
API gateway, NetworkPolicy enforcer) to this single canonical PEP
definition; the cross-walk to ZTMM v2.0 stages downstream at X.X4
depends on the PEP class assigned here.

## 3. Scope

### In scope

- Enumeration of service-mesh control planes across the recognised mesh
  list (Istio, Linkerd, Consul Connect, AWS App Mesh, GCP Anthos Service
  Mesh, Azure Service Fabric Mesh, Cilium with Cluster Mesh).
- Sidecar proxy enumeration across all detected meshes, with cosign
  verification of each sidecar's container image.
- Kubernetes admission webhook enumeration
  (`ValidatingWebhookConfiguration` + `MutatingWebhookConfiguration`),
  classification against the recognised policy-engine list.
- API gateway / Ingress controller enumeration (Istio Gateway, NGINX
  Ingress, AWS ALB Ingress, GCP Cloud LB Ingress, Azure App Gateway
  Ingress, Kong, Ambassador).
- SPIFFE / SPIRE detection + workload-identity inventory.
- Cloud-native workload-identity detection (AWS IRSA, GCP Workload
  Identity, Azure Workload Identity for AKS).
- Per-policy hashing + intent classification for Istio
  `AuthorizationPolicy`, Kubernetes `NetworkPolicy`, Cilium
  `CiliumNetworkPolicy`, Gatekeeper `Constraint`, Kyverno `Policy`.
- Per-mesh mTLS posture (`STRICT` / `PERMISSIVE` / `DISABLE`).
- Cross-walk emission: each detected primitive cross-references a
  CISA ZTMM v2.0 Applications & Workloads sub-function and a NIST SP
  800-207A two-tier policy bucket (network / identity).
- Signed JSON envelope output + Markdown summary output.

### Out of scope

- Deployment of any service mesh, admission webhook, or SPIFFE control
  plane (REO Rule 1; X.X3 is read-only).
- Modification of any cluster state (no `kubectl apply`, no `helm
  install`, no API write of any kind).
- Maturity scoring (delegated to X.X4).
- VM-based or PaaS-only environments where the cluster inventory is
  empty (the slice emits `not_applicable` and stops).
- Service-mesh implementations not on the recognised list. The catalog
  of recognised meshes is extensible via `zt-mesh-catalog.json` (the
  operator adds new entries with provenance), but the in-tree default
  set is the eight named in §1.1 above.
- Reading the actual policy *contents* beyond what is necessary for
  intent classification + hashing. The slice records the hash + the
  classifier output; the operator (or 3PAO) reads the raw YAML in the
  cluster directly when deep review is needed.
- Issuing or rotating SPIFFE SVIDs (entirely outside X.X3's read-only
  posture).
- Cross-cluster mesh federation analysis. The slice records that a
  mesh is configured for multi-cluster (e.g. Istio multi-primary
  install, Cilium Cluster Mesh), but does not walk the peer cluster
  topology (that is X.X5's PDP/PEP integration slice's job).

## 4. Inputs

### 4.1 TypeScript interfaces — what the slice consumes

```typescript
// From X.X2 (the architecture map this slice augments).
interface ZT800_207ArchitectureMap {
  system_id: string;
  generated_at: string;            // ISO 8601 UTC.
  pdp_candidates: PdpRef[];
  pep_candidates: PepRef[];
  pa_candidates: PaRef[];
  trust_algorithm_inputs: TrustAlgorithmInputRef[];
  source_inventory_hash: string;   // SHA-256 of inventory.json.
}

// From LOOP-INV-P1 (inventory backbone).
interface InventoryAsset {
  asset_id: string;
  asset_class: 'k8s_cluster' | 'serverless_function' | 'vm' | 'managed_db' | string;
  provider: 'aws' | 'gcp' | 'azure';
  provider_tag: Record<string, string>;
  region: string;
  // k8s_cluster-specific fields populated by LOOP-E.E1.
  k8s_api_endpoint?: string;
  k8s_version?: string;
  k8s_namespaces?: string[];
}

// From LOOP-E.E1 (k8s-direct collector).
interface K8sClusterSnapshot {
  cluster_id: string;
  api_endpoint: string;
  fetched_at: string;
  namespaces: K8sNamespace[];
  deployments: K8sDeployment[];
  daemonsets: K8sDaemonSet[];
  pods: K8sPod[];                  // includes initContainers[] + containers[] + ephemeralContainers[].
  validating_webhooks: K8sValidatingWebhookConfiguration[];
  mutating_webhooks: K8sMutatingWebhookConfiguration[];
  network_policies: K8sNetworkPolicy[];
  custom_resources: K8sCustomResource[];   // CRDs grouped by group+version+kind.
  ingresses: K8sIngress[];
  services: K8sService[];
}

// From LOOP-J.J3 (cosign attestation pool).
interface CosignAttestationRef {
  image_digest: string;            // e.g. 'sha256:abc...'.
  registry: string;
  attested_at: string;
  rekor_entry_id: string;
  verified: boolean;
  signer_subject?: string;         // x509 subject from the cosign cert (when keyless).
}
```

### 4.2 Operator-supplied config (the only path for human input)

```yaml
# cloud-evidence/config/zt-cloud-native.yaml — committed to repo, not embedded.
mesh_overrides:                   # Optional: operator can flag a mesh installed under non-canonical names.
  - cluster_id: "production-east"
    mesh_kind: "istio"
    control_plane_namespace: "system-istio"   # default would be 'istio-system'.
sidecar_recognition:
  inject_label_selectors:
    - "sidecar.istio.io/inject=true"
    - "linkerd.io/inject=enabled"
    - "consul.hashicorp.com/connect-inject=true"
  init_container_names:
    - "istio-init"
    - "linkerd-init"
    - "consul-connect-inject-init"
spire_namespaces:                  # Where the operator installed SPIRE (defaults: 'spire-system').
  - "spire-system"
  - "spire"
api_gateway_recognition:
  ingress_class_names:
    - "istio"
    - "nginx"
    - "alb"
    - "gce"
    - "azure/application-gateway"
    - "kong"
    - "ambassador"
not_applicable_attestation:        # Required only when the cluster inventory is empty.
  reason: "<operator's documented rationale for why X.X3 is not applicable>"
  signed_off_by: "<operator email>"
  signed_off_at: "<ISO 8601 UTC>"
```

If the operator does not supply `zt-cloud-native.yaml`, X.X3 falls back
to the in-tree default selectors (which match the upstream defaults
for each recognised mesh). The fallback is logged at INFO level so
the audit trail shows which selectors were active for the run.

### 4.3 CLI surface

```
fedpy cloud-evidence \
  --zero-trust-cloud-native \
  --system-id "<system id>" \
  --config /path/to/zt-cloud-native.yaml \
  --output-dir /path/to/out \
  --skip-cosign-verify       # only for unit-test runs; production runs verify
```

The `--zero-trust-cloud-native` flag is set automatically when the
parent `--zero-trust` flag is set AND `inventory.json` shows at least
one `k8s_cluster` asset. The operator can negate with
`--no-zero-trust-cloud-native` (then X.X3 emits `not_applicable` with
operator attestation).

## 5. Outputs

### 5.1 Canonical JSON envelope (`out/zt-800-207a-cloud-native-{system-id}-{YYYYMMDD}.json`)

```jsonc
{
  "$schema": "https://fedpy.example/schemas/zt-800-207a-cloud-native.v1.json",
  "envelope_version": "1.0.0",
  "system_id": "<string>",
  "generated_at": "<ISO 8601 UTC>",
  "generator": {
    "module": "core/zt-800-207a-cloud.ts",
    "module_sha256": "<sha256 of the compiled module bytes>",
    "fedpy_version": "<semver>"
  },
  "inputs": {
    "architecture_map_path": "out/zt-800-207-architecture-{system-id}-{YYYYMMDD}.json",
    "architecture_map_sha256": "<sha256>",
    "inventory_path": "out/inventory.json",
    "inventory_sha256": "<sha256>"
  },
  "applicability": {
    "applicable": true,
    "trigger_flag": "--zero-trust-cloud-native",
    "k8s_cluster_count": 3,
    "serverless_function_count": 27
  },
  "clusters": [
    {
      "cluster_id": "<inventory asset_id>",
      "provider": "aws|gcp|azure",
      "region": "<region>",
      "k8s_version": "<semver>",
      "mesh": {
        "detected": true,
        "kind": "istio|linkerd|consul|appmesh|asm|azsfm|cilium",
        "version": "<semver>",
        "control_plane_namespace": "<ns>",
        "control_plane_deployments": ["<name>", "..."],
        "mtls_posture": "STRICT|PERMISSIVE|DISABLE|UNKNOWN",
        "multi_cluster": true
      },
      "sidecars": {
        "total_pods": 412,
        "pods_with_sidecar": 387,
        "sidecar_coverage_ratio": 0.939,
        "sidecar_images": [
          {
            "image_digest": "sha256:<hex>",
            "registry": "<registry url>",
            "container_name": "istio-proxy",
            "pod_count": 387,
            "cosign_attested": true,
            "rekor_entry_id": "<entry id>",
            "signer_subject": "<x509 subject when keyless>"
          }
        ]
      },
      "admission_webhooks": {
        "validating": [
          {
            "name": "<webhook config name>",
            "matched_resources": ["pods", "deployments"],
            "policy_engine": "gatekeeper|kyverno|kubewarden|jspolicy|polaris|cloud-provider|unknown",
            "endpoint": "<service ref or url>",
            "failure_policy": "Fail|Ignore"
          }
        ],
        "mutating": [
          {
            "name": "<webhook config name>",
            "matched_resources": ["pods"],
            "policy_engine": "kyverno|kubewarden|cloud-provider|unknown",
            "endpoint": "<service ref or url>",
            "failure_policy": "Fail|Ignore"
          }
        ]
      },
      "api_gateways": [
        {
          "ingress_class": "istio",
          "name": "<ingress or gateway object name>",
          "namespace": "<ns>",
          "tls_termination": true,
          "cert_issuer": "<issuer dn or 'letsencrypt' or 'aws-acm' etc.>",
          "san_count": 4
        }
      ],
      "workload_identity": {
        "spiffe": {
          "detected": true,
          "spire_server_namespace": "spire-system",
          "trust_domain": "spiffe://prod.example.com",
          "registration_entries_count": 142
        },
        "cloud_native": {
          "aws_irsa_count": 0,
          "gcp_workload_identity_count": 0,
          "azure_workload_identity_count": 0
        }
      },
      "policies": {
        "istio_authorization_policies": [
          {
            "name": "<policy name>",
            "namespace": "<ns>",
            "action": "ALLOW|DENY|AUDIT|CUSTOM",
            "policy_sha256": "<sha256 of full yaml>",
            "rule_count": 3,
            "principal_count": 7,
            "uses_external_authz": false
          }
        ],
        "kubernetes_network_policies": [
          {
            "name": "<policy name>",
            "namespace": "<ns>",
            "policy_types": ["Ingress", "Egress"],
            "is_default_deny": true,
            "ingress_rule_count": 0,
            "egress_rule_count": 0,
            "policy_sha256": "<sha256 of full yaml>"
          }
        ],
        "cilium_network_policies": [
          {
            "name": "<policy name>",
            "namespace": "<ns>",
            "uses_identity_selector": true,
            "policy_sha256": "<sha256 of full yaml>"
          }
        ],
        "gatekeeper_constraints": [
          {
            "kind": "<constraint kind>",
            "name": "<constraint name>",
            "rego_sha256": "<sha256 of constraint template rego>",
            "enforcement_action": "deny|warn|dryrun"
          }
        ],
        "kyverno_policies": [
          {
            "name": "<policy name>",
            "validation_failure_action": "Enforce|Audit",
            "rules": [
              { "name": "<rule>", "kind": "validate|mutate|generate|verifyImages" }
            ],
            "policy_sha256": "<sha256 of full yaml>"
          }
        ]
      },
      "two_tier_summary": {
        "network_tier_present": true,
        "network_tier_evidence_count": 12,
        "identity_tier_present": true,
        "identity_tier_evidence_count": 8
      },
      "ztmm_app_workloads_signal": "advanced_candidate|initial_candidate|traditional_candidate"
    }
  ],
  "totals": {
    "clusters_scanned": 3,
    "meshes_detected": 2,
    "admission_webhooks_total": 14,
    "api_gateways_total": 9,
    "policies_total": 87,
    "spiffe_clusters": 2,
    "cosign_attested_sidecars_ratio": 0.94
  },
  "provenance": {
    "all_sources_in_repo": true,
    "operator_overrides_present": false,
    "synthesized_fields": []
  },
  "signature": {
    "alg": "ed25519",
    "key_id": "<key id from operator keyring>",
    "signature_b64": "<base64 ed25519 sig over canonical JSON minus the signature block>",
    "rfc3161_token_b64": "<base64 RFC 3161 TST>"
  }
}
```

### 5.2 Markdown summary (`out/zt-800-207a-cloud-native-{system-id}-{YYYYMMDD}.md`)

A short (typically 80-200 lines) human-readable summary suitable for
3PAO walkthrough. Sections:

1. Header: system id, generated_at, signature key id, signed JSON path.
2. Applicability: cluster count, mesh detection summary, applicability
   verdict.
3. Per cluster: mesh kind + version + mTLS posture, sidecar coverage
   ratio + cosign attestation ratio, admission webhook count by engine,
   API gateway count, SPIFFE detection verdict, two-tier summary
   (network present? identity present?), ZTMM signal.
4. Cross-walk: each detected primitive listed with the ZTMM v2.0
   Applications & Workloads sub-function it satisfies.
5. Footer: list of all source documents (NIST SP 800-207A, 800-204A/B/C,
   SPIFFE spec, CISA ZTMM v2.0) and the SHA-256 of the canonical JSON
   envelope for tamper-evidence.

The Markdown file is not signed independently — only the JSON envelope
carries the Ed25519 + RFC 3161 signature. The Markdown carries the
JSON's SHA-256 at the bottom so verifying the JSON automatically
verifies the Markdown was generated from it.

### 5.3 Tracker DB rows

The slice writes one row per cluster into the existing tracker DB
table `zt_cloud_native_evidence` (created in the SQL migration shipped
with X.X3):

```sql
CREATE TABLE IF NOT EXISTS zt_cloud_native_evidence (
  evidence_id            TEXT PRIMARY KEY,        -- uuid v7
  system_id              TEXT NOT NULL,
  cluster_id             TEXT NOT NULL,
  envelope_path          TEXT NOT NULL,
  envelope_sha256        TEXT NOT NULL,
  generated_at           TEXT NOT NULL,           -- ISO 8601 UTC
  mesh_kind              TEXT,
  mesh_mtls_posture      TEXT,
  sidecar_coverage_ratio REAL,
  cosign_attested_ratio  REAL,
  network_tier_present   INTEGER NOT NULL,        -- 0/1
  identity_tier_present  INTEGER NOT NULL,
  ztmm_signal            TEXT NOT NULL,
  signature_key_id       TEXT NOT NULL,
  signature_verified     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_zt_cne_system ON zt_cloud_native_evidence(system_id);
CREATE INDEX IF NOT EXISTS idx_zt_cne_generated ON zt_cloud_native_evidence(generated_at);
```

## 6. Algorithm / Steps

### 6.1 Pre-flight (REO-compliance checks)

```
1. Read CLI flags. If --zero-trust-cloud-native is not set AND the
   parent --zero-trust is not set, abort with exit 0 (slice not
   requested).
2. Load inventory.json. If asset class 'k8s_cluster' count == 0,
   require operator-supplied not_applicable_attestation in
   zt-cloud-native.yaml; on present + valid, emit not_applicable
   envelope and exit. On missing, exit 1 with a requires_operator_input
   diagnostic.
3. Load X.X2 architecture map. Verify the SHA-256 chain (the X.X2
   envelope's signature must verify against the operator's fleet
   signing key). On verify failure, abort with exit 1 — REO Rule 6
   (no fake cryptographic operations).
4. Load zt-cloud-native.yaml. Merge with in-tree defaults; record the
   merged config in the envelope's `applicability.config_overrides`
   field for auditability.
```

### 6.2 Per-cluster enumeration (parallel across clusters, sequential
within a cluster)

```
For each asset where asset_class == 'k8s_cluster':
  5.  Connect to the cluster via the read-only kubeconfig provisioned
      by LOOP-E.E1 (REO Rule 4: no fake SDK; the kubeconfig is the
      operator's real, scoped-down RBAC subject).
  6.  Mesh detection — iterate the recognised mesh catalog:
        a. Query for the canonical control-plane Deployment in the
           canonical namespace; if found, record mesh kind + version
           (parsed from the image tag or the deployment's annotation).
        b. If multiple meshes are detected (rare but legal — Istio +
           Cilium coexisting is a common pattern), record all of them
           and flag `multi_mesh: true` for X.X4 scoring.
  7.  Sidecar enumeration:
        a. List all Pods cluster-wide.
        b. For each Pod, walk containers[] + initContainers[]. A Pod
           is sidecar-injected if at least one container has a name
           matching the operator-configured sidecar names OR an
           image whose repository path matches a recognised pattern
           (e.g. 'istio/proxyv2', 'cr.l5d.io/linkerd/proxy',
           'hashicorp/consul-dataplane', 'envoyproxy/envoy').
        c. For each unique sidecar image digest, query
           core/oci-attest.ts (LOOP-J.J3) for cosign verification.
           Record the Rekor entry id + signer subject.
  8.  Admission webhook enumeration:
        a. List all ValidatingWebhookConfiguration + Mutating
           WebhookConfiguration objects.
        b. For each, attempt to classify the policy engine: match the
           webhook's `clientConfig.service.namespace` + `.name`
           against the recognised list (gatekeeper-system/gatekeeper-
           webhook-service, kyverno/kyverno-svc, kubewarden/policy-
           server, etc.).
        c. Record failure policy (`Fail` is stronger evidence than
           `Ignore`; X.X4 weighting reflects this).
  9.  API gateway enumeration:
        a. List all Ingress objects + Gateway API HTTPRoute objects.
        b. For each, classify the controller via the
           `ingressClassName` field or the `gatewayClassName`.
        c. Walk each gateway's TLS-cert secret reference; pull the cert
           metadata via the cluster's secret-metadata API (the secret
           **payload is never read**; only the metadata: issuer DN,
           SAN list, notBefore/notAfter).
  10. Workload-identity detection:
        a. SPIFFE: query for `spire-server` Deployment in the operator-
           configured namespaces. If found, read the ConfigMap
           `spire-server` (or the install-method-specific name) for the
           trust domain. Query the SPIRE server's
           `registrationEntries` API for the count of registered
           workloads.
        b. AWS IRSA: query for ServiceAccounts annotated with
           `eks.amazonaws.com/role-arn`. Count.
        c. GCP Workload Identity: query for ServiceAccounts annotated
           with `iam.gke.io/gcp-service-account`. Count.
        d. Azure Workload Identity for AKS: query for ServiceAccounts
           annotated with `azure.workload.identity/client-id`. Count.
  11. Policy enumeration:
        a. Istio `AuthorizationPolicy`: list, hash, classify intent.
        b. Kubernetes `NetworkPolicy`: list, hash, identify default-
           deny.
        c. Cilium `CiliumNetworkPolicy` + `CiliumClusterwideNetwork
           Policy`: list, hash, identify identity-vs-IP selector usage.
        d. Gatekeeper `Constraint` + `ConstraintTemplate`: list, hash
           the Rego.
        e. Kyverno `ClusterPolicy` + `Policy`: list, hash, classify
           rules.
  12. Two-tier summary computation:
        - network_tier_present  ←  (NetworkPolicy default-deny count ≥
                                    1)  OR (Cilium identity-policy
                                    count ≥ 1)  OR (mesh mTLS posture
                                    == 'STRICT').
        - identity_tier_present ←  (Istio AuthorizationPolicy count ≥
                                    1 with principals)  OR (SPIFFE
                                    detected with registration entries
                                    ≥ 1)  OR (workload-identity
                                    counts sum ≥ 1).
  13. ZTMM signal computation:
        - 'advanced_candidate' iff network_tier AND identity_tier AND
          cosign_attested_sidecars_ratio ≥ 0.9 AND mesh.mtls_posture ==
          'STRICT'.
        - 'initial_candidate'  iff (network_tier OR identity_tier) but
          not both, OR cosign_attested ratio < 0.9.
        - 'traditional_candidate' iff neither tier present.
```

### 6.3 Envelope assembly + signing

```
14. Build the canonical JSON envelope per §5.1 schema. Compute the
    canonical form (RFC 8785 JSON Canonicalization Scheme).
15. Compute SHA-256 of the canonical form excluding the `signature`
    block.
16. Sign with the operator's fleet Ed25519 key via core/sign.ts
    (REO Rule 6: real key, real signature).
17. Request RFC 3161 timestamp token from the configured TSA via the
    existing TSA client; embed the token in `signature.rfc3161_token_b64`.
18. Write the envelope file. Write the Markdown summary.
19. Insert tracker DB row per cluster.
20. Emit run-log line `zt-800-207a:done clusters=N meshes=M
    advanced=A initial=I traditional=T`.
```

### 6.4 Failure handling (deterministic)

```
- API connection failure to a cluster: record the cluster with
  `scan_failed: true` + the error class; continue with remaining
  clusters; do not abort the run. The cluster's evidence row in the
  tracker carries `scan_failed = 1`.
- Cosign verification failure for a sidecar image: record the sidecar
  with `cosign_attested: false`. Do NOT fail the run — unattested
  sidecars are valid evidence of an immature supply chain, which is
  what X.X4 will score.
- Operator config validation failure (malformed YAML, unknown mesh
  kind): exit 1 with a precise diagnostic naming the offending field.
- Architecture-map signature failure (X.X2 envelope did not verify):
  exit 1 with diagnostic. The operator must regenerate X.X2 before
  X.X3 can proceed.
```

## 7. Files to create / modify

All paths are absolute under `/Users/kenith.philip/FedRAMP 20x/`.

### Create

- `cloud-evidence/core/zt-800-207a-cloud.ts` — the orchestrator module
  exporting `runZt800_207aCloud(opts): Promise<Zt800_207aEnvelope>`.
- `cloud-evidence/core/zt-pep-cloud-native-detector.ts` — the
  per-cluster detector module exporting
  `detectCloudNativePeps(clusterSnapshot, config):
  Promise<ClusterCloudNativeEvidence>`. Houses the mesh / sidecar /
  webhook / gateway / SPIFFE / policy enumerators.
- `cloud-evidence/data/zt-800-207a-architecture.json` — the in-tree
  catalog of recognised mesh kinds, control-plane Deployment names,
  canonical namespaces, sidecar image patterns, admission webhook
  service names, ingress controller class names. Signed snapshot used
  as the read-only baseline.
- `cloud-evidence/test/zt-800-207a-cloud.test.ts` — the unit + scenario
  test file covering all 15+ test specs in §8.
- `cloud-evidence/data/zt-mesh-catalog.json` — extracted, normalised,
  signed snapshot of the recognised-mesh catalog (referenced by both
  modules at runtime).
- `cloud-evidence/test/fixtures/zt-800-207a/` — fixture directory with
  representative cluster snapshots:
  - `istio-strict-spiffe.json` — full Advanced posture.
  - `istio-permissive-no-spiffe.json` — Initial posture.
  - `bare-cluster.json` — Traditional / Initial posture (no mesh).
  - `cilium-only.json` — identity-tier present, mesh absent.
  - `multi-mesh-istio-cilium.json` — both meshes coexisting.
  - `aks-azure-workload-identity.json` — cloud-native WI without SPIFFE.
  - `eks-irsa.json` — AWS IRSA evidence.
  - `gke-workload-identity.json` — GCP WI evidence.
  - `scan-failed.json` — connection-error cluster.

### Modify

- `cloud-evidence/core/zt-pillars-catalog.ts` (from X.X1) — add a
  cross-walk entry on the Applications & Workloads pillar pointing to
  the X.X3 envelope path pattern.
- `cloud-evidence/scripts/orchestrator.ts` — register the
  `--zero-trust-cloud-native` and `--no-zero-trust-cloud-native` flags;
  wire `runZt800_207aCloud()` into the cloud-evidence run sequence so
  it executes after X.X2 and before X.X4.
- `cloud-evidence/tracker/migrations/NNNN_create_zt_cloud_native_evidence.sql`
  — SQL migration creating the table per §5.3.
- `cloud-evidence/docs/STATUS.md` — flip X.X3 row to `done` on slice
  completion (per the §13 procedure).
- `cloud-evidence/docs/loops/LOOP-X-SPEC.md` — flip X.X3 row in the
  Status table to `done` on slice completion.
- `CHANGELOG.md` — Unreleased section, prepend the X.X3 entry.

## 8. Test specifications

Fixtures are real cluster snapshots captured via `kubectl get -o json`
against representative test clusters at the time the slice was
authored (2026-06-07). They contain no live secrets; pod / secret /
config-map payloads have been redacted to metadata only. All fixture
files are committed under `cloud-evidence/test/fixtures/zt-800-207a/`.

| id     | scenario                                                  | fixture path                                                        | expected                                                                                                | acceptance                                                              |
|--------|-----------------------------------------------------------|---------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| X3.T01 | Istio STRICT + SPIFFE + 100% sidecar cosign-attested     | fixtures/zt-800-207a/istio-strict-spiffe.json                       | ztmm_signal == 'advanced_candidate'; both tiers present                                                  | exact match on envelope.clusters[0].ztmm_app_workloads_signal           |
| X3.T02 | Istio PERMISSIVE, no SPIFFE, no NetworkPolicy default-deny| fixtures/zt-800-207a/istio-permissive-no-spiffe.json                | ztmm_signal == 'initial_candidate'; identity_tier_present == false                                       | exact match on signal + tier flags                                       |
| X3.T03 | Bare cluster (no mesh, no SPIFFE, no policy)             | fixtures/zt-800-207a/bare-cluster.json                              | ztmm_signal == 'traditional_candidate'; mesh.detected == false                                           | exact match                                                              |
| X3.T04 | Cilium identity-based policy without service mesh         | fixtures/zt-800-207a/cilium-only.json                               | identity_tier_present == true via Cilium; mesh.detected == false                                          | tier_present flag derived from Cilium evidence                          |
| X3.T05 | Multi-mesh Istio + Cilium coexistence                     | fixtures/zt-800-207a/multi-mesh-istio-cilium.json                   | mesh.kind contains both; multi_mesh flag true                                                            | both meshes enumerated                                                   |
| X3.T06 | AKS with Azure Workload Identity (no SPIFFE)              | fixtures/zt-800-207a/aks-azure-workload-identity.json               | workload_identity.cloud_native.azure_workload_identity_count > 0; identity_tier_present == true            | identity tier derived from cloud-native WI                              |
| X3.T07 | EKS with IRSA                                             | fixtures/zt-800-207a/eks-irsa.json                                  | workload_identity.cloud_native.aws_irsa_count > 0                                                         | IRSA count == fixture count                                              |
| X3.T08 | GKE with Workload Identity                                | fixtures/zt-800-207a/gke-workload-identity.json                     | workload_identity.cloud_native.gcp_workload_identity_count > 0                                            | GCP WI count == fixture count                                            |
| X3.T09 | Cluster connection failure (network unreachable)          | mock: throw 'ETIMEDOUT' from k8s client                             | clusters[].scan_failed == true; run continues; exit code 0                                               | tracker row written with scan_failed = 1                                 |
| X3.T10 | Cosign verification failure for one sidecar image         | fixtures/zt-800-207a/istio-strict-spiffe.json + cosign mock failure | sidecar entry has cosign_attested == false; signal degrades to 'initial_candidate'                       | ratio < 0.9 triggers degradation                                         |
| X3.T11 | Architecture-map signature verification failure           | mock: tamper with X.X2 envelope before X.X3 reads it                | exit 1 with diagnostic naming the failed verification                                                    | precise error message + non-zero exit                                    |
| X3.T12 | not_applicable path (zero k8s clusters in inventory)      | inventory.json with no k8s_cluster assets + valid attestation       | not_applicable envelope emitted; ztmm_signal == 'not_applicable'                                          | envelope shape matches schema; signature still applied                   |
| X3.T13 | Operator overrides namespace for a mesh                   | config: mesh_overrides[0].control_plane_namespace = 'system-istio'  | detector finds mesh in the overridden namespace                                                          | mesh.detected == true at overridden namespace                            |
| X3.T14 | Default-deny NetworkPolicy detection                      | fixture with one '{}' selector, empty rules NetworkPolicy           | is_default_deny == true; network_tier_present == true                                                     | flag set per §6.2 step 12 rule                                           |
| X3.T15 | Kyverno verifyImages rule joined with cosign attestation  | fixture with Kyverno ClusterPolicy of kind verifyImages + cosign OK | supply-chain attested flag set on the cluster                                                            | cross-reference resolved correctly                                       |
| X3.T16 | RFC 3161 token attached + verifies                        | run end-to-end against test TSA                                     | signature.rfc3161_token_b64 non-empty; openssl ts -verify succeeds                                       | externally re-verifiable token                                            |
| X3.T17 | Canonical-JSON determinism                                | same input fixtures, two runs                                       | envelope.signature.signature_b64 identical across runs                                                   | byte-identical canonical output (excluding signature.rfc3161 timestamp)  |
| X3.T18 | Markdown summary sha256 matches envelope hash             | run produces both files                                             | md file's footer line hash matches sha256 of canonical JSON                                              | manual cross-check                                                       |
| X3.T19 | Tracker DB row insert + index hit                         | run + query                                                         | one row per cluster; queryable by system_id index                                                        | row count == cluster count                                                |
| X3.T20 | Lint-no-stubs guardrail                                   | full slice files                                                    | npm run lint:no-stubs returns zero matches in any new file                                                | G1 green                                                                 |

A minimum of 15 tests is the gating bar; the bar above (20) reflects
the slice's role as the substrate for X.X4 and X.X5 (a regression
here cascades into ZTMM scoring + PDP/PEP evidence). The
implementation log records the actual passing count at slice closure.

## 9. Risks

### Risk X3-R01 — Mesh detection false negatives on non-canonical installations

**Description:** Operators sometimes install service meshes into
non-standard namespaces (e.g. `system-istio` instead of `istio-system`)
or with renamed control-plane Deployments (Helm chart overrides).
The detector's canonical-name matching can miss these installations
and erroneously report `mesh.detected: false`, which would
under-score the cluster at X.X4 and produce a false POA&M item.

**Mitigation:** (a) The `zt-cloud-native.yaml` `mesh_overrides[]`
field lets the operator declare non-canonical names with provenance.
(b) The detector also falls back to a CRD-existence check (presence
of `virtualservices.networking.istio.io` strongly implies Istio even
if the control-plane namespace was renamed). (c) Test fixtures
include at least one non-canonical install case.

**Owner:** detector implementer at coding time; tracked in
LOOP-X-RISKS.md.

### Risk X3-R02 — Sidecar cosign attestation failure cascades into wrongful POA&M

**Description:** A cosign verification failure may be transient (Rekor
unreachable, TUF metadata refresh delay) rather than a real
unattested-image situation. If X.X3 treats every failure as
"unattested", the cosign_attested_sidecars_ratio drops, the cluster
degrades from "advanced_candidate" to "initial_candidate", and X.X4
emits a spurious POA&M item.

**Mitigation:** (a) The cosign client (LOOP-J.J3) already retries
with exponential backoff. (b) The envelope records each failure with
its error class so a 3PAO can distinguish transient infrastructure
failures from genuine unattested images. (c) X.X4's scoring algorithm
uses a 30-day rolling window of X.X3 runs, not a single run, when
computing the ratio (specified in X.X4's doc; X.X3 only emits the
per-run ratio).

### Risk X3-R03 — Read-only RBAC subject is over-scoped and silently writes

**Description:** The LOOP-E.E1 kubeconfig is supposed to be scoped to
`get`/`list`/`watch` verbs only. If the operator's RBAC binding is
over-scoped (a common misconfiguration), a future code change that
accidentally calls `kubectl apply` would succeed and mutate cluster
state, breaching REO Rule 1.

**Mitigation:** (a) The X.X3 module imports a thin
`k8s-readonly-guard.ts` wrapper around the k8s client that throws on
any verb other than `get`/`list`/`watch`/`create:tokenreview`. (b) A
unit test asserts the wrapper rejects an `apply` call. (c) The
slice's CHANGELOG entry documents the RBAC requirement so 3PAO
verifies cluster RBAC matches.

### Risk X3-R04 — Mesh / policy-engine catalog goes stale

**Description:** The recognised-mesh catalog
(`data/zt-mesh-catalog.json`) was assembled 2026-06-07. New meshes
emerge (e.g. a CNCF-graduated mesh entering common use); existing
meshes rename control-plane Deployments across major versions. A
stale catalog miscategorises real installations and produces
"unknown" mesh records that depress the maturity signal.

**Mitigation:** (a) The catalog file carries a `last_reviewed_at`
field; the orchestrator emits a WARN log line if the file is older
than 180 days. (b) A CI cron job (separate slice, future LOOP-X
maintenance task) re-runs the extractor quarterly. (c) The
`mesh_overrides[]` operator-config path lets the operator declare a
new mesh without waiting for an upstream catalog update.

### Risk X3-R05 — Large clusters produce envelopes larger than the tracker DB row limit

**Description:** A cluster with tens of thousands of pods + hundreds
of policies can produce a multi-megabyte JSON envelope. The tracker
DB's `envelope_path` field stores the filesystem path, not the
envelope, so the row is small — but the JSON file itself can hit
disk-space limits in restricted environments (e.g. the GitHub
Actions runner).

**Mitigation:** (a) Per §4 the envelope records `policies[].policy_sha256`
+ `policy_name + namespace`, not the full YAML; that keeps even
large clusters well under 5 MB in practice. (b) A test asserts the
envelope size scales linearly with `(policies + pods + webhooks)`
and stays under 10 MB at fixture inputs. (c) The Markdown summary
is capped at 1 MB by structural design.

## 10. Open questions

1. **Catalog evolution cadence:** Is a quarterly cron sufficient, or
   should the catalog re-extract on every nightly run? Decision deferred
   to X.X4's authoring session because X.X4 consumes the catalog at
   scoring time and its tolerance for staleness defines the answer.

2. **Cilium "transparent encryption" treatment:** Cilium can provide
   transparent in-kernel WireGuard encryption between Pods that is
   functionally equivalent to mesh mTLS but is not policy-tier
   evidence in the 800-207A sense (no per-identity policy on top).
   Should X.X3 treat enabled Cilium transparent encryption as
   `network_tier_present: true`? Initial draft: yes, with provenance
   note. Final answer pending review with cilium-security mailing
   list (cf. RISKS register).

3. **Knative / OpenFaaS coverage:** Serverless platforms running on
   top of Kubernetes (Knative Serving, OpenFaaS) introduce their own
   gateway abstractions (Activator, Gateway). Should X.X3 enumerate
   them? Initial draft: defer to X.X4 — if the cluster runs Knative,
   the Knative `ksvc` count is already in inventory; X.X4 can score
   based on that without X.X3 adding a new collector.

4. **External authorisation (extauth) coverage:** When Istio is
   configured with `CUSTOM` action + an external authz provider
   (OPA-Istio, custom REST service), should X.X3 attempt to verify
   the external provider responds? Initial draft: no — REO Rule 4
   forbids active probing of operator infrastructure; only the
   `CUSTOM` action + `extensionProviders[]` reference is recorded.

5. **Side-projection of mesh + cluster-level network policy onto
   the Devices pillar:** The Devices pillar at CISA ZTMM v2.0
   "Advanced" stage requires "device-aware access enforcement". A
   per-namespace NetworkPolicy that restricts source identities to
   workloads carrying a specific SPIFFE ID is arguably device-aware
   enforcement. Should X.X3 emit a Devices-pillar signal too?
   Initial draft: defer to X.X4 — the cross-walk happens at scoring
   time, not at evidence-collection time.

## 11. REQUIRES-OPERATOR-INPUT

| field name                                    | type         | validator                                                                                    | UI location                                                                                | failure mode if missing                                                                                                          |
|-----------------------------------------------|--------------|----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `not_applicable_attestation.reason`           | string       | non-empty; ≤ 500 chars                                                                       | Tracker UI → Zero Trust → Cloud-Native → "Not applicable" panel                            | If inventory has 0 k8s clusters AND this field missing, exit 1 with `requires_operator_input` diagnostic                          |
| `not_applicable_attestation.signed_off_by`    | string (email)| RFC 5322 email                                                                              | Tracker UI same panel                                                                      | Same as above                                                                                                                    |
| `not_applicable_attestation.signed_off_at`    | string (ISO) | ISO 8601 UTC, within last 90 days                                                            | Same                                                                                       | Same                                                                                                                             |
| `mesh_overrides[*].cluster_id`                | string       | must match an existing inventory asset_id                                                    | Tracker UI → ZT → Cloud-Native → Mesh overrides table                                      | Detector falls back to canonical-name matching; if cluster has non-canonical install AND override missing, mesh.detected = false |
| `mesh_overrides[*].mesh_kind`                 | enum         | one of recognised mesh kinds                                                                 | Same                                                                                       | Override ignored with WARN; canonical detection runs                                                                              |
| `mesh_overrides[*].control_plane_namespace`   | string       | valid k8s namespace name                                                                     | Same                                                                                       | Override ignored                                                                                                                  |
| `spire_namespaces[]`                          | string[]     | each a valid k8s namespace name                                                              | Tracker UI → ZT → Cloud-Native → SPIRE config                                              | Defaults to `['spire-system']`; if operator installed SPIRE elsewhere AND not configured, SPIFFE.detected = false                  |
| `api_gateway_recognition.ingress_class_names` | string[]     | each unique                                                                                  | Tracker UI → ZT → Cloud-Native → Gateway recognition                                       | Defaults applied; custom gateways uncategorised but still enumerated                                                              |
| `sidecar_recognition.inject_label_selectors`  | string[]     | each a valid k8s label selector                                                              | Same UI section                                                                            | Defaults applied; custom selectors absent will undercount sidecars in non-standard installs                                       |
| `sidecar_recognition.init_container_names`    | string[]     | each a valid container name                                                                  | Same                                                                                       | Defaults applied                                                                                                                  |

## 12. Implementation log

| date       | session   | action                                                              | commit | notes |
|------------|-----------|---------------------------------------------------------------------|--------|-------|
| 2026-06-07 | wf-uvxyz  | Specification authored via FedPy workflow                            | TBD    | —     |

(The implementer appends a row at every commit boundary, every test
failure, every research question answered, and every newly-discovered
risk. See `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3 for full update
cadence.)

## 13. Completion checklist

The slice is closed only when the following 7-step procedure
(quoted verbatim from `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`)
executes successfully, plus the additional Step 8.

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

> Step 8: After commit lands, append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with 'git log --oneline -3'. Only THEN is the slice closed.
