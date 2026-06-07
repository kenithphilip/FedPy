---
slice_id: L.L2
title: Inherited-controls tracker + Leveraged-Authorization enumeration
loop: L
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A0 SSP-1/SSP-2, LOOP-A.A4, INV-P1, INV-P2, INV-S2, INV-S3, providers/{aws,gcp,azure}/discover.ts, providers/{aws,gcp,azure}/reference-arch.ts]
blocks: [L.L1 (inherited rows), L.L3, L.L4, C.C9, Q.Q1]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# L.L2 — Inherited-controls tracker + Leveraged-Authorization enumeration

## TL;DR
Discover which FedRAMP-Authorized IaaS/PaaS providers (AWS GovCloud, GCP Assured Workloads, Azure Government, etc.) are leveraged by this CSO from real `inventory.json`, resolve their PA-ids against a committed lookup, build a per-control `inheritance-trace.json` from an operator-committed YAML (one entry per provider × per inherited control), emit one OSCAL Component Definition document per leveraged authorization, and wire `system-implementation.leveraged-authorizations[]` + `back-matter.resources[type=service]` into the OSCAL SSP. This is the upstream slice that lets L.L1 populate the "Inherited" column of the CIS/CRM workbook with real, citation-backed entries (not stubs).

## Status
- Status: pending
- Commit: — (filled when shipped, per `docs/SLICE-COMPLETION-PROCEDURE.md`)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
L.L2 closes the leveraged-authorization wiring gap in the OSCAL SSP and provides the ground-truth inheritance map for the rest of LOOP-L. Every value emitted traces to either (a) real `inventory.json` discovery, (b) the committed `docs/leveraged-authorizations.generated.json` PA-id lookup, (c) the operator's committed `config/leveraged-authorizations.yaml` per-provider per-control inheritance map, or (d) a visible `REQUIRES-OPERATOR-INPUT` marker — per REO Rule 4. Concrete ties:

- **(a) Cloud evidence collection**: `inventory.json` from `providers/{aws,gcp,azure}/discover.ts` is the discovery source. AWS partition (`aws-us-gov` vs `aws`), GCP `assured_workloads_enabled`, Azure subscription `cloud` (`AzureUSGovernment` vs `AzureCloud`) are the discriminants.
- **(b) KSI envelopes**: not consumed directly by L.L2 (L.L1 reads KSI evidence for Service-Provider rows). But the leveraged-authorization map filters which controls are even *available* for `service-provider` classification in L.L1 Step C — a control fully inherited cannot also be claimed CSP-implemented without dual-attestation.
- **(c) OSCAL chain (SSP/AP/AR/POA&M)**: L.L2 extends `core/oscal-ssp.ts` to populate `metadata.parties[]` (one per leveraged provider), `system-implementation.leveraged-authorizations[]`, and `back-matter.resources[type=service]`. Emits one OSCAL Component Definition document per provider (validated against the committed v1.1.2 schema via `core/oscal-validate.ts`).
- **(d) FRMR catalog**: not consumed directly; the operator's YAML names the controls inherited (per provider, per impact tier). NIST Rev5 catalog (`core/nist-r5.ts`) validates every cited `control_id` against the canonical Rev5 set.
- **(e) Tracker DB**: not consumed in first ship; future LOOP-L extension may add tracker UI for inheritance authoring. First ship is operator-committed yaml.
- **(f) Sign + timestamp**: `out/leveraged-authorizations.json`, `out/inheritance-trace.json`, and every `out/components/*.component-definition.json` ride existing `core/sign.ts` + `core/timestamp.ts` pipelines.

## Why this slice exists
L.L1 emits `responsibility = 'inherited'` rows. Without L.L2, those rows have nowhere to point — the `inherited_from_pa_id` field is `REQUIRES-OPERATOR-INPUT` for every inherited control, the workbook is unsubmittable, and the OSCAL SSP's `system-implementation.leveraged-authorizations[]` is an empty array (FedRAMP-noncompliant when the CSO sits on AWS / GCP / Azure, which essentially all production CSOs do).

NIST SP 800-53 Rev5 §2.5:
> "Controls are inheritable when their implementation is the responsibility of an external system, organization, or service. Inherited controls are documented in the security plan along with the identifier of the providing entity and a description of the inherited control."

The "identifier of the providing entity" maps to OSCAL's `leveraged-authorization.uuid` + `props[name=fedramp-pa-id]`. The "description of the inherited control" maps to the per-component `inherited[].description` element + the per-control narrative L.L4 will render in SSP §13. L.L2 produces the structured record that NIST 800-53 §2.5 demands, in a form FedRAMP's OSCAL converter consumes.

FedRAMP "Important Considerations" (Rev5):
> "Control authors should clearly indicate which portions of the security control are inherited and provide a description of what is inherited."

The `inheritance_scope` field (`full` / `partial` / `hybrid`) on each `InheritedControl` is the structured manifestation of the "which portions" requirement.

## Authoritative sources (with verbatim quotes)

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/ — **OSCAL SSP v1.1.2** — `system-implementation.leveraged-authorizations[]` element. Required fields per the schema:
  > "uuid (string, UUID v4) — a machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this leveraged authorization."
  > "title (string) — the title or name of the leveraged authorization."
  > "party-uuid (string, UUID v4) — a reference to a party defined in metadata."
  > "date-authorized (string, ISO date)."

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/component-definition/json-reference/ — **OSCAL Component Definition v1.1.2**:
  > "A collection of component descriptions, which may optionally be grouped by capability."
  > Each `components[]` entry has `uuid`, `type` ('service' for IaaS/PaaS), `title`, `description`, `purpose` (FedRAMP convention), `props[]`, `links[]`, `responsible-roles[]`, `control-implementations[]`.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf — **NIST SP 800-37 Rev2 §2.5 (Control Inheritance)**:
  > "Common controls are inherited by one or more organizational information systems. Authorization is generally inherited from the organization providing the common control to the organization leveraging it."
  > "Controls inheritance is an effective way for organizations to reduce the cost of implementing security and privacy controls by leveraging the work already performed by other organizations (e.g., common control providers)."

- https://aws.amazon.com/compliance/services-in-scope/FedRAMP/ — **AWS Services in Scope (FedRAMP)** — authoritative list of AWS services authorized at Moderate / High in AWS US-East/West (Commercial) and AWS GovCloud. PA-ID `F1411040093` historically associated with AWS GovCloud per `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.10; operator verifies against the current FedRAMP Marketplace listing at ship time.

- https://cloud.google.com/security/compliance/fedramp — **GCP FedRAMP page** — Assured Workloads authorization for High; Commercial GCP for Moderate. PA-IDs operator-confirmed from marketplace.fedramp.gov.

- https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-fedramp — **Azure FedRAMP page**:
  > "Both Azure and Azure Government maintain FedRAMP High P-ATOs issued by the JAB in addition to more than 400 Moderate and High ATOs issued by individual federal agencies for the in-scope services."

- https://marketplace.fedramp.gov/ — **FedRAMP Marketplace** — single source of truth for current PA-ids. Operator confirms each lookup-table entry against the marketplace listing at shipping time (per `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.10).

- https://github.com/usnistgov/OSCAL/blob/main/json/schema/oscal_component-definition_schema.json — **OSCAL Component Definition JSON schema (v1.1.2)** — committed to `cloud-evidence/docs/oscal/oscal_component-definition_schema.v1.1.2.json` for ajv validation.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inheritance-trace.ts` — pure builder + disk emitter for `out/inheritance-trace.json` and `out/leveraged-authorizations.json`. ~350 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/leveraged-auth-discovery.ts` — derives in-scope leveraged providers from `inventory.json` + `providers/*/reference-arch.ts`. ~250 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-component-def.ts` — pure builder + per-provider OSCAL Component Definition emitter. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/leveraged-auth-config.ts` — typed loader for `config/leveraged-authorizations.yaml`. ~200 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/leveraged-authorizations.example.yaml` — committed example YAML (one entry per provider with inherited control list per impact tier).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/leveraged-authorizations.generated.json` — committed lookup table mapping `(provider, region, impact_level)` → `pa_id` + `marketplace_url`. One entry per known provider per impact tier per audit §5.10.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/oscal/oscal_component-definition_schema.v1.1.2.json` — committed OSCAL Component Definition schema (downloaded from NIST OSCAL repo).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/inheritance-trace.test.ts` — pure builder tests + integration tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/leveraged-auth-discovery.test.ts` — discovery tests against fixture inventory.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/oscal-component-def.test.ts` — Component Definition emitter tests including ajv schema validation.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/leveraged-auth-config.test.ts` — YAML loader tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/leveraged-auth/` — fixture inventory.json + YAML + expected output.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — populate `metadata.parties[]` (one per leveraged provider), `system-implementation.leveraged-authorizations[]` from `out/leveraged-authorizations.json`, and `back-matter.resources[type=service]` with `rlinks[]` pointing at each emitted component-definition file.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--leveraged-auth` flag + env `CLOUD_EVIDENCE_LEVERAGED_AUTH`; `--leveraged-auth-config <path>` defaulting to `config/leveraged-authorizations.yaml`. Runs AFTER inventory collection AND BEFORE `--crm` and `--oscal-ssp`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `leveraged-authorizations-json` (filename `leveraged-authorizations.json`), `inheritance-trace-json` (filename `inheritance-trace.json`), and `oscal-component-definition` (filename_pattern `components/*.component-definition.json` — uses the same glob-style pattern as `ksi-evidence`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-validate.ts` — extend with ajv schema validation for Component Definition v1.1.2.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sections/SECTION-A.md` — add A24 (Component Definition documents) row to artifact inventory.

## Schemas / standards
- **OSCAL SSP v1.1.2 `system-implementation.leveraged-authorizations[]`** — required fields:
  - `uuid` (string, UUID v4)
  - `title` (string)
  - `party-uuid` (string, UUID v4 — references `metadata.parties[].uuid`)
  - `date-authorized` (string, ISO date — leveraged provider's authorization date)
  - `links[]` (optional, with `rel: 'leveraged-authorization-package'`)
  - `props[]` (extension point for `fedramp-pa-id`, `impact-level`)
  - `remarks` (optional, markdown)
- **OSCAL Component Definition v1.1.2 `components[]`** — required fields per entry:
  - `uuid`, `type: 'service'`, `title`, `description`, `purpose` (FedRAMP convention)
  - `props[]` — `fedramp-pa-id`, `service-name`, `service-region`
  - `responsible-roles[]` — role-id `'provider'` + party-uuid of the leveraged provider
  - `control-implementations[]` — one entry per impact tier (low/moderate/high) the provider exposes for inheritance; each enumerates the controls
- **FedRAMP party convention** — leveraged provider represented in SSP `metadata.parties[]` as `type: 'organization'`, with `props[]` carrying `fedramp-pa-id`, `cloud`, `region`. Namespace `FEDRAMP_NS` already defined in `core/oscal-ssp.ts`.
- **PA-id format** — FedRAMP-issued identifier; regex `^F\d{10}$` (historic example `F1411040093` for AWS GovCloud per audit §5.10).
- **`leveraged-authorizations.generated.json`** committed lookup structure:
  ```json
  {
    "version": 1,
    "fetched_at": "2026-06-07",
    "source": "https://marketplace.fedramp.gov/",
    "entries": [
      {
        "provider": "aws",
        "deployment": "aws-govcloud",
        "region": "us-gov-west-1",
        "impact_level": "high",
        "pa_id": "F1411040093",
        "title": "AWS GovCloud (US-West)",
        "marketplace_url": "https://marketplace.fedramp.gov/products/F1411040093",
        "pa_id_source": "fedramp-marketplace",
        "date_authorized": "REQUIRES-OPERATOR-INPUT",
        "operator_confirmed": false
      }
    ]
  }
  ```
  Operator confirms each entry against marketplace.fedramp.gov before shipping; `operator_confirmed: true` is a precondition for `--strict-crm`.

## Build steps (concrete, numbered)

1. Define typed interfaces in `core/inheritance-trace.ts`:
   ```ts
   export interface LeveragedAuthorization {
     uuid: string;                       // UUID v4, generated per run
     pa_id: string;                      // 'F1411040093'
     title: string;                      // 'AWS GovCloud'
     provider: 'aws' | 'gcp' | 'azure' | string;
     deployment: 'aws-govcloud' | 'aws-commercial' | 'gcp-assured-workloads' | 'gcp-commercial' | 'azure-government' | 'azure-commercial';
     date_authorized: string;            // ISO date
     impact_level: 'low' | 'moderate' | 'high';
     region: string;                     // 'us-gov-west-1'
     party_uuid: string;                 // matches SSP metadata.parties[].uuid
     marketplace_url?: string;
     source: 'config-yaml' | 'lookup-table' | 'REQUIRES-OPERATOR-INPUT';
     pa_id_source: 'fedramp-marketplace' | 'operator-confirmed' | 'REQUIRES-OPERATOR-INPUT';
   }

   export interface InheritedControl {
     control_id: string;                 // 'AC-2', 'AC-2(1)'
     inherited_from_pa_id: string;
     inherited_from_uuid: string;        // LeveragedAuthorization.uuid
     inheritance_scope: 'full' | 'partial' | 'hybrid';
     inheritance_description: string;
     source: 'config-yaml' | 'REQUIRES-OPERATOR-INPUT';
   }

   export interface InheritanceTrace {
     metadata: {
       generated_at: string;
       cis_crm_format_version: '20x.crm.preview.2026';
       impact_tier: 'low' | 'moderate' | 'high';
     };
     leveraged_authorizations: LeveragedAuthorization[];
     inherited_controls: InheritedControl[];
     by_control: Record<string, InheritedControl[]>;  // control_id → entries
     provenance: { emitter: 'core/inheritance-trace.ts'; emittedAt: string; sourceCalls: string[]; signingKeyId?: string };
   }
   ```

2. `leveraged-auth-discovery.ts` — pure builder:
   ```ts
   export type Deployment =
     | 'aws-commercial' | 'aws-govcloud'
     | 'gcp-commercial' | 'gcp-assured-workloads'
     | 'azure-commercial' | 'azure-government';
   export interface DiscoveryInputs {
     inventory: Inventory;
     awsReferenceArch?: AwsReferenceArch;
     gcpReferenceArch?: GcpReferenceArch;
     azureReferenceArch?: AzureReferenceArch;
   }
   export interface DiscoveryResult {
     deployments: Deployment[];
     evidence: Array<{ deployment: Deployment; sourceCall: string; sample_asset_id: string; sample_field: string; sample_value: string }>;
   }
   export function discoverLeveragedAuthorizations(inputs: DiscoveryInputs): DiscoveryResult;
   ```
   **Discovery rules** (concrete and source-cited):
   - `aws-commercial`: any asset with `provider === 'aws'` AND `account_partition === 'aws'`.
   - `aws-govcloud`: any asset with `provider === 'aws'` AND `account_partition === 'aws-us-gov'`.
   - `gcp-commercial`: any asset with `provider === 'gcp'` AND `project_metadata.parent.type === 'organizations'` AND NOT `assured_workloads_enabled === true`.
   - `gcp-assured-workloads`: any asset with `provider === 'gcp'` AND `assured_workloads_enabled === true`.
   - `azure-commercial`: any asset with `provider === 'azure'` AND `subscription_metadata.cloud === 'AzureCloud'`.
   - `azure-government`: any asset with `provider === 'azure'` AND `subscription_metadata.cloud === 'AzureUSGovernment'`.
   Each evidence entry records the asset id + field + value that triggered the classification — every deployment is traceable to ≥1 real inventory asset.

3. `leveraged-auth-config.ts` — typed YAML loader:
   ```yaml
   version: 1
   providers:
     aws-govcloud:
       title: AWS GovCloud (US-West)
       date_authorized: '2018-04-15'
       impact_level: high
       region: us-gov-west-1
       marketplace_url: https://marketplace.fedramp.gov/products/F1411040093
       inherited_controls:
         AC-2:
           inheritance_scope: partial
           description: |
             AWS IAM service implements the underlying account lifecycle …
         AC-2(1):
           inheritance_scope: full
           description: |
             AWS IAM automation implements account management lifecycle …
   ```
   Validation rules:
   - `inherited_controls.*` control_id must exist in NIST Rev5 catalog (`core/nist-r5.ts`).
   - `inheritance_scope` ∈ {`full`, `partial`, `hybrid`}.
   - Every deployment named here must also be in `docs/leveraged-authorizations.generated.json`; otherwise loader throws.

4. `inheritance-trace.ts` — pure builder:
   ```ts
   export function buildInheritanceTrace(
     leveraged: LeveragedAuthorization[],
     config: LeveragedAuthYaml,
     impactTier: 'low' | 'moderate' | 'high',
   ): InheritanceTrace;
   ```
   For each `LeveragedAuthorization`, walk the yaml's `inherited_controls[]` for that deployment; validate every control_id; build `by_control` index for O(1) lookup by L.L1 + L.L3.

5. `oscal-component-def.ts` — per-provider emitter:
   ```ts
   export function buildComponentDefinition(
     leveraged: LeveragedAuthorization,
     inherited: InheritedControl[],
   ): OscalComponentDefinition;
   export async function emitComponentDefinitions(
     trace: InheritanceTrace,
     outDir: string,
   ): Promise<{ paths: string[]; validated: number }>;
   ```
   Emits one file per `LeveragedAuthorization` at `out/components/<deployment>-<region>.component-definition.json`. Each file is validated by `core/oscal-validate.ts` against `docs/oscal/oscal_component-definition_schema.v1.1.2.json` via ajv; emit fails fast if validation fails.

6. **PA-id resolution**:
   ```ts
   export function resolvePaId(
     deployment: Deployment,
     impactTier: 'low' | 'moderate' | 'high',
     lookup: LeveragedAuthLookup,
   ): { pa_id: string; title: string; region: string; marketplace_url?: string; source: 'lookup-table' | 'REQUIRES-OPERATOR-INPUT' };
   ```
   On miss (no entry matches `(deployment, impact_level)` in the lookup), returns `pa_id: 'REQUIRES-OPERATOR-INPUT'`, `source: 'REQUIRES-OPERATOR-INPUT'` — never fabricates a PA-id.

7. **SSP integration** (`core/oscal-ssp.ts` extension) — inside `buildOscalSsp()`:
   ```ts
   const tracePath = path.join(outDir, 'inheritance-trace.json');
   if (fs.existsSync(tracePath)) {
     const trace: InheritanceTrace = JSON.parse(fs.readFileSync(tracePath, 'utf-8'));
     for (const la of trace.leveraged_authorizations) {
       ssp.metadata.parties.push({
         uuid: la.party_uuid,
         type: 'organization',
         name: la.title,
         props: [
           { name: 'fedramp-pa-id', ns: FEDRAMP_NS, value: la.pa_id },
           { name: 'cloud', ns: FEDRAMP_NS, value: la.provider },
           { name: 'region', ns: FEDRAMP_NS, value: la.region },
         ],
       });
       ssp['system-implementation']['leveraged-authorizations'].push({
         uuid: la.uuid,
         title: la.title,
         'party-uuid': la.party_uuid,
         'date-authorized': la.date_authorized,
         links: la.marketplace_url
           ? [{ href: la.marketplace_url, rel: 'leveraged-authorization-package' }]
           : [{ href: `#component-${la.uuid}`, rel: 'leveraged-authorization-package' }],
         props: [
           { name: 'fedramp-pa-id', ns: FEDRAMP_NS, value: la.pa_id },
           { name: 'impact-level', ns: FEDRAMP_NS, value: la.impact_level },
         ],
       });
       ssp['back-matter'].resources.push({
         uuid: `component-${la.uuid}`,
         type: 'service',
         title: la.title,
         rlinks: [{ href: `./components/${la.deployment}-${la.region}.component-definition.json` }],
       });
     }
   }
   ```

8. **Orchestrator wiring**: `--leveraged-auth` runs AFTER inventory collection (which seeds `inventory.json`) AND BEFORE `--crm`, `--oscal-ssp`, and `--ssp-docx`. Documented order in `core/orchestrator.ts`: collect → inventory → leveraged-auth → inheritance-trace → crm → ssp → ap → ar → poam → bundle → sign → timestamp. The flag implies neither `--crm` nor `--oscal-ssp`; either can run independently if the operator only wants the trace.

9. **Strict mode**: `--strict-crm` (introduced in L.L1) ALSO aborts if discovery surfaces a deployment for which the lookup table has no PA-id (i.e. `leveraged-authorizations.generated.json` missing entry OR `operator_confirmed: false`).

10. **Bundler integration** — add to `submission-bundle.ts:WELL_KNOWN`:
    ```ts
    { role: 'leveraged-authorizations-json', filename: 'leveraged-authorizations.json', description: 'Per-leveraged-provider inheritance map (LOOP-L.L2)', required: false },
    { role: 'inheritance-trace-json', filename: 'inheritance-trace.json', description: 'Per-control inheritance trace (LOOP-L.L2)', required: false },
    { role: 'oscal-component-definition', filename_pattern: 'components/*.component-definition.json', description: 'OSCAL Component Definition for each leveraged authorization (LOOP-L.L2)', required: false },
    ```
    `required: false` because some CSOs are not leveraged (e.g. an on-prem CSO with no IaaS dependency); strict-bundle does NOT require these when discovery returns zero deployments. When discovery returns ≥1 deployment AND any of the three is missing, the bundler flags it.

11. **Provenance** — every emitted file carries `provenance` block: emitter name, `emittedAt`, `sourceCalls` (inventory.json path, yaml path, lookup table path, ajv schema path), `signingKeyId` placeholder filled by `core/sign.ts`.

12. **Validation pass**:
    - Run every `components/*.component-definition.json` through `oscal-validate.ts` (ajv against `oscal_component-definition_schema.v1.1.2.json`).
    - Run `inheritance-trace.json` + `leveraged-authorizations.json` through `scripts/check-provenance.mjs`.
    - Run modified SSP through existing OSCAL SSP ajv validator — new `leveraged-authorizations[]` + `back-matter.resources[type=service]` entries must keep SSP valid.

13. **Sign + timestamp**: all emitted artifacts ride existing `core/sign.ts` + `core/timestamp.ts` glob; signed manifest catches all of them.

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4 (`cloud-evidence/CLAUDE.md`):

| Field | Source | Behavior when missing |
|---|---|---|
| PA-id per `(deployment, impact_level)` | `docs/leveraged-authorizations.generated.json` lookup | If lookup missing entry OR `operator_confirmed: false`, `pa_id: 'REQUIRES-OPERATOR-INPUT'`, `pa_id_source: 'REQUIRES-OPERATOR-INPUT'`; `--strict-crm` aborts run with the deployment name in error message |
| Per-control inheritance (which controls inherit from a provider) | `config/leveraged-authorizations.yaml` `inherited_controls[]` per deployment | Per-control entry absent → control simply not inherited (no marker — fine if operator hasn't transcribed yet); L.L3 gap report flags any control with `responsibility = 'inherited'` AND yaml entry missing |
| `marketplace_url` | YAML OR lookup | Optional; absence does NOT mark REQUIRES-OPERATOR-INPUT |
| `date_authorized` | YAML OR lookup | If absent in BOTH, `date_authorized: 'REQUIRES-OPERATOR-INPUT'`; SSP emitter flags with prop `date-authorized-source: 'REQUIRES-OPERATOR-INPUT'` |
| `inheritance_scope` (full/partial/hybrid) per inherited control | YAML | Required when control is inherited; loader throws if missing |
| `inheritance_description` per inherited control | YAML | Required when control is inherited; loader throws if missing |
| `impact_level` per deployment | YAML | Required; loader throws if missing |
| `operator_confirmed: true` in lookup | Operator commits change to `docs/leveraged-authorizations.generated.json` after checking marketplace.fedramp.gov | Until `true`, `--strict-crm` refuses to ship |

## Test specifications (≥12 tests)

1. `it('discovers aws-govcloud from inventory asset with account_partition aws-us-gov')` — fixture inventory has one EC2 asset with `account_partition === 'aws-us-gov'`; assert `deployments` includes `aws-govcloud` + evidence cites the asset id.
2. `it('discovers gcp-assured-workloads from assured_workloads_enabled flag')` — fixture GCE asset with `assured_workloads_enabled === true`; assert `deployments` includes `gcp-assured-workloads`.
3. `it('discovers azure-government from subscription cloud AzureUSGovernment')` — fixture Azure VM in `AzureUSGovernment`; assert deployment.
4. `it('discovers aws-commercial when partition is aws (default)')` — fixture EC2 with `account_partition === 'aws'`; assert `deployments` includes `aws-commercial`.
5. `it('returns empty deployments when no leveraged inventory present')` — fixture with only on-prem assets (no provider field); assert `deployments` is empty.
6. `it('resolves PA-id from leveraged-authorizations.generated.json lookup for confirmed entry')` — fixture lookup has `aws-govcloud/high` with `operator_confirmed: true` and pa_id `F1411040093`; assert resolved pa_id matches.
7. `it('marks pa_id REQUIRES-OPERATOR-INPUT when lookup missing entry')` — fixture lookup omits Azure entry; discovery surfaces `azure-government`; assert pa_id `'REQUIRES-OPERATOR-INPUT'`, source `'REQUIRES-OPERATOR-INPUT'`.
8. `it('marks pa_id REQUIRES-OPERATOR-INPUT when lookup entry has operator_confirmed=false')` — fixture has entry with `operator_confirmed: false`; assert pa_id marker set even though pa_id string present in lookup.
9. `it('--strict-crm aborts with deployment name in error message when PA-id missing')` — assert thrown error includes deployment string + non-zero exit code.
10. `it('YAML loader reads inherited control list per provider')` — fixture YAML has 5 inherited controls for `aws-govcloud`; assert 5 `InheritedControl` rows in trace.
11. `it('YAML loader rejects entry with control_id not in NIST Rev5 catalog')` — fixture has `AC-99` (nonexistent); assert thrown error names AC-99.
12. `it('YAML loader rejects entry with inheritance_scope outside {full, partial, hybrid}')` — fixture has `inheritance_scope: complete`; assert loader throws.
13. `it('YAML loader rejects entry with missing inheritance_description')` — fixture omits description; assert throw.
14. `it('emits inheritance-trace.json with by_control index populated')` — assert `by_control['AC-2']` equals the expected `InheritedControl` rows.
15. `it('emits one component-definition file per leveraged authorization')` — fixture has 2 deployments; assert 2 files in `out/components/`.
16. `it('component-definition file validates against oscal_component-definition_schema.v1.1.2.json via ajv')` — load schema + ajv + emitted file; assert valid.
17. `it('SSP system-implementation.leveraged-authorizations[] populated after L.L2 runs')` — fixture inventory + yaml; run L.L2 then SSP emitter; assert array has correct length + entries.
18. `it('SSP metadata.parties[] gains one entry per leveraged provider')` — assert parties array bumped.
19. `it('SSP back-matter.resources[type=service] entries point at component-definition files')` — assert `rlinks[0].href` matches expected relative path.
20. `it('emits provenance block on leveraged-authorizations.json + inheritance-trace.json')` — `check:provenance` passes.
21. `it('bundler well-known catalogue includes all 3 new roles')` — assert role table contains `leveraged-authorizations-json`, `inheritance-trace-json`, `oscal-component-definition`.
22. `it('REO no-stubs check: no TODO/FIXME/placeholder tokens in production code')` — runs `npm run lint:no-stubs`.

## REO compliance specific to this slice
- Leveraged-auth discovery reads REAL `inventory.json`; never assumes a provider that isn't enumerated by the existing INV-P1..S6 collectors.
- PA-ids come from the committed lookup table OR a `REQUIRES-OPERATOR-INPUT` marker; never fabricated. Lookup entries require `operator_confirmed: true` before they're usable under strict mode.
- Inherited control lists come from operator YAML; never silently defaulted to "all of them" or to a hard-coded inheritance assumption.
- Component Definition files validated against the OSCAL v1.1.2 schema before emit — invalid files never land on disk.
- Signed by existing `core/sign.ts` pipeline; every emitted file in the manifest glob.
- Provenance block on every emitted file per REO Rule 2.6 + `scripts/check-provenance.mjs`.
- No `process.env.NODE_ENV === 'test'` branches in production paths (REO Rule 1.8); tests inject seams via dependency-injected file readers + dependency-injected runId.
- `cis_crm_format_version: '20x.crm.preview.2026'` pinned (matches L.L1 + audit §5.5).

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/inheritance-trace.test.ts tests/core/leveraged-auth-discovery.test.ts tests/core/oscal-component-def.test.ts tests/core/leveraged-auth-config.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: Committed PA-id lookup may go stale** — FedRAMP Marketplace listings can be revoked, suspended, or re-issued. Mitigation: `pa_id_source: 'fedramp-marketplace'` + `operator_confirmed` flag in the lookup; CHANGELOG calls out the date of the lookup snapshot; future LOOP-E (ConMon) slice may add automated marketplace polling.
- **Risk 2: Operator transcription error in YAML** — operator transcribing the provider's published CRM into yaml could mis-attribute a control. Mitigation: NIST Rev5 control_id validation (loader throws on unknown ids); inheritance_scope enforced enum; CHANGELOG documents the source provider CRM version + date. Future: automated parser of the published JSON form when FedRAMP standardises one.
- **Risk 3: OSCAL Component Definition schema may not be fetchable at build time** — NIST repository availability not 100%. Mitigation: schema is committed under `docs/oscal/` (offline-resilient).
- **Risk 4: Inventory may use unexpected partition / cloud strings** — e.g. AWS adds a new partition like `aws-iso-b` for IC. Mitigation: discovery rules are a typed enum; unknown partition logs a warning + skips classification (does NOT silently classify as Commercial); future slice adds the new partition explicitly.
- **Risk 5: Component Definition impact-tier vs CSO impact tier mismatch** — provider may be FedRAMP-High but the CSO is Moderate (the CSO inherits only the Moderate subset). Mitigation: trace records both `provider.impact_level` and `cso.impact_tier`; yaml `inherited_controls[]` is scoped to the CSO's tier; CHANGELOG documents the resolution rule.
- **Risk 6: Multi-cloud CSO with overlapping inherited controls** — control `AC-2` inherited from both AWS and GCP. Mitigation: `by_control['AC-2']` is an array (not a single value); L.L4 narrative composes a "shared inheritance" paragraph naming both providers.
- **Risk 7: Lookup-table commit history accidentally exposes embargoed PA-ids** — typically not embargoed but theoretically possible. Mitigation: only commit confirmed marketplace-public entries; runbook documents.
- **Risk 8: `--strict-crm` blocking on PA-id missing creates a chicken-and-egg first-run problem** — operator can't ship without an entry, but doesn't know which to add until first run. Mitigation: non-strict mode emits everything with markers; operator copies the marker list into the lookup; subsequent run uses strict.

## Open questions
- **Q1**: Should the lookup table be `docs/leveraged-authorizations.generated.json` (committed) or `config/leveraged-authorizations.lookup.json` (gitignored)? Recommend: `docs/` committed — the PA-id list is FedRAMP public knowledge; non-secret; sharing across teams is a feature.
- **Q2**: How do we handle a deployment that the lookup table has at impact level Moderate but the CSO operates at High? Recommend: skip + log warning; operator must add a High entry to the lookup. Test pinned.
- **Q3**: For partial inheritance (`inheritance_scope: partial`), should the OSCAL `by-component.inherited[].description` include the "partial" qualifier, or should the renderer choose? Recommend: emitter writes `description = "[Partial inheritance] " + scope + ": " + description` so OSCAL consumers see the partial flag without a custom prop.
- **Q4**: For deployment `aws-commercial` at Moderate, is FedRAMP commercial AWS authorized? Recommend: yes per AWS services-in-scope page; lookup entry `aws-commercial/moderate` with the appropriate PA-id (operator confirms).
- **Q5**: Should the OSCAL Component Definition file path be `<deployment>-<region>` or `<pa_id>`? Recommend: `<deployment>-<region>` for human readability; `pa_id` is a prop inside the file.
- **Q6**: Does the FedRAMP Marketplace expose a JSON API for PA-id lookup? Recommend: investigate during build; if yes, future slice can refresh the lookup table mechanically; if no, the manual operator-confirmed workflow stays.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses, per docs/IMPLEMENTATION-LOG-TEMPLATE.md)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥22 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-L-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added per LOOP-L-SPEC.md §12 template
- [ ] Commit with slice ID in message ("LOOP-L.L2: Inherited-controls tracker + Leveraged-Authorization enumeration")
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-L-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-L-SPEC.md` §3 (Dependencies) and §5 L.L2 spec for cross-loop context.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/oscal-ssp.ts` — your extension point for `leveraged-authorizations[]` + `back-matter.resources[]`.
6. Read `cloud-evidence/core/oscal-validate.ts` — pattern for ajv-based schema validation; extend with Component Definition schema.
7. Read `cloud-evidence/core/inventory.ts` (or `providers/{aws,gcp,azure}/discover.ts`) — your discovery source.
8. Read `cloud-evidence/core/submission-bundle.ts:WELL_KNOWN` — add 3 new entries (one uses `filename_pattern`).
9. Read `cloud-evidence/core/nist-r5.ts` — Rev5 catalog for control_id validation.
10. Read `cloud-evidence/docs/loops/LOOP-L-RISKS.md` — live risks register.
11. Read `cloud-evidence/docs/ADDITIONAL-LOOPS-AUDIT.md §5.10` — original PA-id lookup-table motivation.
12. Begin implementation; update Implementation log section as you go.

---
