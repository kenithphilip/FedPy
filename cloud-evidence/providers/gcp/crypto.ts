/**
 * GCP Using-Cryptographic-Modules collector — UCM family (UCM-CSX-CMD / -CAT / -UVM).
 *
 * Mirrors providers/aws/crypto.ts for GCP. STRICTLY READ-ONLY: only .list/.get
 * on Cloud KMS, SSL policies, and (best-effort) BackendService SSL-policy usage.
 *
 * Signals:
 *   - Cloud KMS cryptoKeys protectionLevel:
 *       SOFTWARE -> BoringCrypto (FIPS 140-3 Level 1, CMVP cert #5104) — validated
 *       HSM      -> Cloud HSM (FIPS 140-2 Level 3) — validated
 *       EXTERNAL / EXTERNAL_VPC -> operator-supplied module — needs CMVP proof
 *   - compute.sslPolicies minTlsVersion / profile (FIPS posture proxy for in-transit)
 *
 * Impact level is read from process.env.CLOUD_EVIDENCE_IMPACT_LEVEL (default
 * 'moderate'); the UCM-CSX-UVM key word + severity scale by it (Low MAY /
 * Moderate SHOULD / High MUST), via the AWS-side helpers re-exported here.
 *
 * Every external call is wrapped with diagnoseGcpError on failure, naming the
 * exact GCP role/permission the runner principal must hold.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier } from '../../core/envelope.ts';
import type { ImpactTier } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';
import { impactLevelFromEnv, keyWordForUcm, severityForUcm, type CmvpEntry } from '../aws/crypto.ts';

// Re-export the level helpers so a single import path covers both providers.
export { impactLevelFromEnv, keyWordForUcm, severityForUcm } from '../aws/crypto.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

interface Ctx { project: string; }
function setupCtx(c: CollectorContext): Ctx {
  if (!c.gcp?.project_id) throw new Error('GCP collector invoked without project_id');
  return { project: c.gcp.project_id };
}

// =====================================================================
// CMVP reference table for GCP.
// Cert numbers cited from cloud-evidence/docs/analysis/pva-scg-ucm.md.
// =====================================================================
export const GCP_CMVP_REFERENCE: Record<string, CmvpEntry> = {
  boringcrypto: {
    module: 'BoringCrypto (Google) — backs Cloud KMS SOFTWARE keys',
    cert: '5104',
    standard: 'FIPS 140-3',
    level: 1,
    active: true,
    note: 'protectionLevel=SOFTWARE Cloud KMS keys + the default in-transit TLS stack use BoringCrypto. Also applies to FIPS-mode GKE node pools.',
  },
  cloud_hsm: {
    module: 'Google Cloud HSM (Marvell/Cavium)',
    cert: '3490',
    standard: 'FIPS 140-2',
    level: 3,
    active: true,
    note: 'protectionLevel=HSM Cloud KMS keys. FIPS 140-2 Level 3.',
  },
};

/** Map a GCP KMS protectionLevel to its CMVP backing (or null = needs manual proof). */
function cmvpForProtectionLevel(level: string | null | undefined): CmvpEntry | null {
  if (level === 'SOFTWARE') return GCP_CMVP_REFERENCE.boringcrypto!;
  if (level === 'HSM') return GCP_CMVP_REFERENCE.cloud_hsm!;
  return null; // EXTERNAL / EXTERNAL_VPC => operator must attach CMVP proof.
}

/** A GCP SSL policy is FIPS-adequate if it forbids legacy TLS (min >= TLS 1.2) and is not COMPATIBLE. */
function isAdequateSslPolicy(minTls: string | null | undefined, profile: string | null | undefined): boolean {
  const modernMin = minTls === 'TLS_1_2' || minTls === 'TLS_1_3';
  const strongProfile = profile === 'MODERN' || profile === 'RESTRICTED';
  return modernMin && strongProfile;
}

export async function collectUcm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const level: ImpactTier = impactLevelFromEnv();
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ---------------------------------------------------------------
  // 1. Cloud KMS cryptoKeys: protectionLevel inventory.
  // ---------------------------------------------------------------
  interface KmsKeyRecord {
    name: string;
    purpose?: string;
    protectionLevel?: string | null;
    cmvpModule: string | null;
    cmvpCert: string | null;
    cmvpActive: boolean | null;
  }
  const kmsKeys: KmsKeyRecord[] = [];
  try {
    const kms = await gcpAuth.googleClient<any>('cloudkms', 'v1');
    const locations = ['global', 'us', 'us-central1', 'us-east1', 'us-west1', 'europe-west1'];
    for (const loc of locations) {
      try {
        const rings = await kms.projects.locations.keyRings.list({ parent: `projects/${ctx.project}/locations/${loc}` });
        for (const ring of rings.data.keyRings ?? []) {
          const ks = await kms.projects.locations.keyRings.cryptoKeys.list({ parent: ring.name });
          for (const k of ks.data.cryptoKeys ?? []) {
            // protectionLevel lives on the version template (and on the primary version).
            const pl: string | null | undefined = k.versionTemplate?.protectionLevel ?? k.primary?.protectionLevel ?? null;
            const cmvp = cmvpForProtectionLevel(pl);
            kmsKeys.push({
              name: k.name,
              purpose: k.purpose,
              protectionLevel: pl,
              cmvpModule: cmvp?.module ?? null,
              cmvpCert: cmvp?.cert ?? null,
              cmvpActive: cmvp ? cmvp.active : null,
            });
          }
        }
      } catch (e) {
        // A location with no key rings / not enabled is expected — only surface real perm errors.
        const msg = diagnoseGcpError(e, `cloudkms.cryptoKeys.list (${loc})`, 'cloudkms.cryptoKeys.list (roles/cloudkms.viewer)');
        if (/PERMISSION_DENIED|UNAUTHENTICATED/.test(msg)) warnings.push(msg);
      }
    }
    evidence.push(ev('cloudkms.crypto_module_inventory', kmsKeys));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudkms.projects.locations.keyRings.list', 'cloudkms.keyRings.list (roles/cloudkms.viewer)')); }

  const kmsExternalKeys = kmsKeys.filter((k) => k.cmvpModule === null);
  const kmsValidatedKeys = kmsKeys.filter((k) => k.cmvpModule !== null);

  // ---------------------------------------------------------------
  // 2. compute.sslPolicies: in-transit TLS posture (FIPS proxy).
  // ---------------------------------------------------------------
  interface SslPolicyRecord { name: string; minTlsVersion?: string | null; profile?: string | null; adequate: boolean; }
  const sslPolicies: SslPolicyRecord[] = [];
  try {
    const compute = await gcpAuth.googleClient<any>('compute', 'v1');
    try {
      const r = await compute.sslPolicies.list({ project: ctx.project });
      for (const p of r.data.items ?? []) {
        sslPolicies.push({
          name: p.name,
          minTlsVersion: p.minTlsVersion,
          profile: p.profile,
          adequate: isAdequateSslPolicy(p.minTlsVersion, p.profile),
        });
      }
    } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.sslPolicies.list', 'compute.sslPolicies.list (roles/compute.viewer)')); }
    evidence.push(ev('compute.ssl_policy_inventory', sslPolicies));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute (client init)', 'compute.sslPolicies.list (roles/compute.viewer)')); }

  const inadequateSslPolicies = sslPolicies.filter((p) => !p.adequate);

  // ---------------------------------------------------------------
  // Alternative satisfiers (UCM-wide).
  // ---------------------------------------------------------------
  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Cloud HSM keys (FIPS 140-2 Level 3, CMVP cert #3490)',
      description: 'protectionLevel=HSM Cloud KMS keys are CMVP-validated at a higher level than SOFTWARE; an acceptable UVM module.',
      evidence_required: ['cloudkms cryptoKeys with protectionLevel=HSM', 'Mapping of federal-data keys to HSM-backed keys'],
      detected: kmsKeys.some((k) => k.protectionLevel === 'HSM'),
      detection_signals: kmsKeys.filter((k) => k.protectionLevel === 'HSM').map((k) => `${k.name} protectionLevel=HSM`),
    },
    {
      via: 'External Key Manager (EKM) / dedicated HSM vendor with its own CMVP cert',
      description: 'protectionLevel=EXTERNAL/EXTERNAL_VPC keys route to an operator-supplied module. Validated iff its active CMVP certificate is attached.',
      evidence_required: ['EKM vendor module CMVP certificate number + active status', 'Mapping of federal-data keys to the EKM'],
      detected: kmsKeys.some((k) => k.cmvpModule === null),
      detection_signals: kmsExternalKeys.map((k) => `${k.name} protectionLevel=${k.protectionLevel ?? 'EXTERNAL'} (needs CMVP proof)`),
    },
    {
      via: 'Subprocessor CMVP inheritance',
      description: 'Federal-data crypto handled by a subprocessor whose modules are CMVP-validated; inherited via attestation. Signal lives in core/subprocessors-sheet.ts.',
      evidence_required: ['Subprocessor CMVP attestation in the subprocessors sheet', 'Cert number + active status'],
      detected: false,
      detection_signals: [],
    },
    {
      via: 'FIPS-enabled GKE node pools / app-layer BoringCrypto (CMVP #5104)',
      description: 'App-layer TLS/at-rest crypto via BoringCrypto in FIPS mode. Not fully cloud-API-visible — supply node-pool flags / build config as artifact.',
      evidence_required: ['GKE node-pool FIPS flag or build config', 'BoringCrypto CMVP cert', 'Runtime FIPS-mode assertion'],
      detected: false,
      detection_signals: [],
    },
  ];

  // ---------------------------------------------------------------
  // Findings.
  // ---------------------------------------------------------------
  const nistControls = ['sc-13', 'sc-12', 'sc-8'];

  // ---- UCM-CSX-CMD: inventory proxy (MUST) ----
  const inventoryBuilt = kmsKeys.length + sslPolicies.length > 0;
  const cmdFinding = finding({
    rule: 'gcp.ucm.cmd.crypto_module_inventory_built',
    passed: inventoryBuilt,
    severity: 'high',
    applicable_key_word: 'MUST',
    current: {
      summary: inventoryBuilt
        ? `Built a CMVP-labeled inventory: ${kmsKeys.length} Cloud KMS key(s) (${kmsValidatedKeys.length} validated-module-backed, ${kmsExternalKeys.length} EXTERNAL/manual), ${sslPolicies.length} SSL policy/policies.`
        : 'No cloud-native cryptographic modules observed via Cloud KMS / SSL policies. Either the runner lacks read permission, no crypto services exist, or federal-data crypto lives in the app layer / a subprocessor (document those separately).',
      observations: {
        kms: kmsKeys.map((k) => ({ name: k.name, purpose: k.purpose, protectionLevel: k.protectionLevel, cmvp_module: k.cmvpModule, cmvp_cert: k.cmvpCert, cmvp_active: k.cmvpActive })),
        ssl_policies: sslPolicies,
        cmvp_reference_table: GCP_CMVP_REFERENCE,
      },
    },
    target: {
      summary: 'A documented inventory maps every cryptographic service that protects federal customer data to its backing module and CMVP status {validated | update-stream | not-validated}.',
      rationale: 'UCM-CSX-CMD MUST. NIST SC-13/SC-12. Cloud KMS SOFTWARE=BoringCrypto (CMVP #5104), HSM=Cloud HSM (CMVP #3490).',
    },
    gap: inventoryBuilt ? undefined : {
      description: 'No crypto-module inventory could be built from cloud-native reads. Coverage may be incomplete (app-layer + subprocessor modules are not cloud-API-visible).',
      affected_resources: [{ type: 'google_kms_crypto_key', identifier: 'none', attributes: {} }],
    },
    remediation: inventoryBuilt ? undefined : {
      summary: 'Confirm read permissions, then document app-layer and subprocessor modules to complete the inventory.',
      options: [
        {
          approach: 'Grant the runner cloudkms.viewer + compute.viewer and re-run; then hand-author app-layer/subprocessor rows.',
          mechanism: 'terraform',  // IaC delivery
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'none', notes: 'Read-only.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Inventory authoring.' },
          steps: [
            'Grant roles/cloudkms.viewer and roles/compute.viewer to the runner principal.',
            'Re-run the collector to populate cloud-native modules.',
            'Add rows for app-layer crypto and subprocessor modules with their CMVP cert numbers.',
          ],
          references: [{ title: 'GCP FIPS 140 validated', url: 'https://cloud.google.com/security/compliance/fips-140-2-validated' }],
        },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: nistControls,
  });

  // ---- UCM-CSX-CAT: default-tenant config selects validated-module crypto (SHOULD) ----
  const catPasses = kmsExternalKeys.length === 0 && inadequateSslPolicies.length === 0;
  const catFinding = finding({
    rule: 'gcp.ucm.cat.agency_tenant_defaults_validated',
    passed: catPasses,
    severity: 'medium',
    applicable_key_word: 'SHOULD',
    current: {
      summary: catPasses
        ? `Default crypto selections resolve to validated modules: 0 EXTERNAL-protectionLevel keys, ${inadequateSslPolicies.length} inadequate SSL policy/policies.`
        : `Some defaults select non-validated-module crypto: ${kmsExternalKeys.length} EXTERNAL-protectionLevel key(s), ${inadequateSslPolicies.length} SSL policy/policies below TLS 1.2 / MODERN.`,
      observations: {
        external_keys: kmsExternalKeys.map((k) => ({ name: k.name, protectionLevel: k.protectionLevel })),
        inadequate_ssl_policies: inadequateSslPolicies,
      },
    },
    target: {
      summary: 'Agency-tenant CMEK defaults use protectionLevel SOFTWARE (BoringCrypto) or HSM (both CMVP-validated), and SSL policies enforce >= TLS 1.2 with a MODERN/RESTRICTED profile.',
      rationale: 'UCM-CSX-CAT SHOULD. NIST SC-13/CM-6. Secure-by-default validated crypto for federal tenants.',
    },
    gap: catPasses ? undefined : {
      description: 'Default-tenant crypto can land federal data on a non-validated module / weak TLS even though a validated option is available.',
      affected_resources: [
        ...kmsExternalKeys.map<AffectedResource>((k) => ({ type: 'google_kms_crypto_key', identifier: k.name, name: k.name, attributes: { protectionLevel: k.protectionLevel } })),
        ...inadequateSslPolicies.map<AffectedResource>((p) => ({ type: 'google_compute_ssl_policy', identifier: p.name, name: p.name, attributes: { minTlsVersion: p.minTlsVersion, profile: p.profile } })),
      ],
    },
    remediation: catPasses ? undefined : {
      summary: 'Pin CMEK protectionLevel SOFTWARE/HSM and a >= TLS 1.2 MODERN SSL policy in the tenant-provisioning baseline.',
      options: [
        {
          approach: 'Set CMEK + SSL policy defaults in the landing-zone IaC.',
          mechanism: 'terraform',  // IaC delivery
          owner_team: 'Platform',
          cost_impact: { level: 'low', notes: 'HSM keys cost more than SOFTWARE; both validated.' },
          availability_impact: { level: 'medium', notes: 'Stricter TLS may break very old clients; validate against your matrix.' },
          customer_visible: { level: 'low', notes: 'Stronger TLS for agency tenants.' },
          effort_estimate: { magnitude: 'days', notes: 'Baseline change + rollout.' },
          steps: [
            'Default agency-project CMEK keys to protectionLevel SOFTWARE or HSM (avoid EXTERNAL unless the EKM module has an active CMVP cert).',
            'Create/attach a compute SSL policy with min_tls_version=TLS_1_2 and profile=MODERN (or RESTRICTED).',
          ],
          example_code: `resource "google_compute_ssl_policy" "agency" {
  name            = "agency-modern-tls"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}
resource "google_kms_crypto_key" "agency" {
  name             = "agency-data"
  key_ring         = google_kms_key_ring.agency.id
  purpose          = "ENCRYPT_DECRYPT"
  version_template { protection_level = "SOFTWARE" }  # BoringCrypto, CMVP #5104
}`,
          references: [{ title: 'Compute SSL policies', url: 'https://cloud.google.com/load-balancing/docs/ssl-policies-concepts' }],
        },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['sc-13', 'cm-6'],
    cross_ksi_dependencies: [
      { ksi_id: 'SCG-CSO-SDF', relationship: 'shares-remediation', note: 'Validated-crypto defaults are part of the secure-defaults baseline.' },
    ],
  });

  // ---- UCM-CSX-UVM: actually USE validated modules (level-scaled) ----
  const uvmKeyWord = keyWordForUcm(level);
  const uvmSeverity = severityForUcm(level);
  const inactiveValidatedKeys = kmsKeys.filter((k) => k.cmvpActive === false);
  let uvmViolations: AffectedResource[] = [];
  if (level === 'high') {
    uvmViolations = [
      ...kmsExternalKeys.map<AffectedResource>((k) => ({ type: 'google_kms_crypto_key', identifier: k.name, name: k.name, attributes: { protectionLevel: k.protectionLevel, reason: 'non-validated module (needs CMVP proof)' } })),
      ...inactiveValidatedKeys.map<AffectedResource>((k) => ({ type: 'google_kms_crypto_key', identifier: k.name, name: k.name, attributes: { cmvp_cert: k.cmvpCert, reason: 'CMVP validation inactive' } })),
      ...inadequateSslPolicies.map<AffectedResource>((p) => ({ type: 'google_compute_ssl_policy', identifier: p.name, name: p.name, attributes: { minTlsVersion: p.minTlsVersion, profile: p.profile, reason: 'weak TLS policy' } })),
    ];
  } else if (level === 'moderate') {
    uvmViolations = [
      ...kmsExternalKeys.map<AffectedResource>((k) => ({ type: 'google_kms_crypto_key', identifier: k.name, name: k.name, attributes: { protectionLevel: k.protectionLevel, reason: 'validated SOFTWARE/HSM available but EXTERNAL used without CMVP proof' } })),
    ];
  } // low: leave empty (MAY)

  const uvmPasses = level === 'low' ? true : uvmViolations.length === 0;
  const validatedCryptoCount = kmsValidatedKeys.length + sslPolicies.filter((p) => p.adequate).length;
  const totalCryptoCount = kmsKeys.length + sslPolicies.length;
  const coveragePct = totalCryptoCount === 0 ? null : Math.round((validatedCryptoCount / totalCryptoCount) * 100);

  const uvmFinding = finding({
    rule: 'gcp.ucm.uvm.uses_validated_cryptographic_modules',
    passed: uvmPasses,
    severity: uvmSeverity,
    applicable_key_word: uvmKeyWord,
    current: {
      summary: totalCryptoCount === 0
        ? `No in-scope cloud-native crypto observed. UCM-CSX-UVM is ${uvmKeyWord} at impact level '${level}'.`
        : `At impact level '${level}' (${uvmKeyWord}): ${coveragePct}% of observed cloud-native crypto resolves to an active CMVP-validated module (${validatedCryptoCount}/${totalCryptoCount}). ${level === 'low' ? 'Reported informationally (MAY).' : `${uvmViolations.length} in-scope service(s) do not use a validated module.`}`,
      observations: {
        impact_level: level,
        applicable_key_word: uvmKeyWord,
        coverage_pct: coveragePct,
        validated_kms_keys: kmsValidatedKeys.map((k) => ({ name: k.name, protectionLevel: k.protectionLevel, cert: k.cmvpCert })),
        external_kms_keys: kmsExternalKeys.map((k) => ({ name: k.name, protectionLevel: k.protectionLevel })),
        inactive_validation_keys: inactiveValidatedKeys.map((k) => ({ name: k.name, cert: k.cmvpCert })),
        adequate_ssl_policies: sslPolicies.filter((p) => p.adequate).map((p) => p.name),
        inadequate_ssl_policies: inadequateSslPolicies,
        cmvp_reference_table: GCP_CMVP_REFERENCE,
      },
    },
    target: {
      summary: level === 'high'
        ? 'Every cryptographic service protecting federal customer data uses a module with an ACTIVE CMVP validation (MUST at High).'
        : level === 'moderate'
          ? 'Where a CMVP-validated module is available, it is used for federal-data crypto (SHOULD at Moderate); exceptions are justified.'
          : 'Validated modules are used where practical (MAY at Low); coverage reported for awareness, never failed.',
      rationale: 'UCM-CSX-UVM has an explicitly published per-level key word (Low MAY / Moderate SHOULD / High MUST). NIST SC-13/SC-12/SC-8. Cloud KMS SOFTWARE=BoringCrypto (CMVP #5104), HSM=Cloud HSM (CMVP #3490).',
    },
    gap: uvmPasses ? undefined : {
      description: `At impact level '${level}', ${uvmViolations.length} cryptographic service(s) do not use an active CMVP-validated module. A failing ${uvmKeyWord} is reported at '${uvmSeverity}' severity.`,
      affected_resources: uvmViolations,
    },
    remediation: uvmPasses ? undefined : {
      summary: 'Move federal-data crypto onto validated modules: CMEK protectionLevel SOFTWARE/HSM, >= TLS 1.2 MODERN SSL policies — or attach CMVP proof for the external/app-layer module in use.',
      options: [
        {
          approach: 'Switch CMEK protectionLevel and tighten SSL policies.',
          mechanism: 'terraform',  // IaC delivery
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'HSM keys cost more; re-encryption minor.' },
          availability_impact: { level: 'medium', notes: 'Re-keying and stricter TLS can affect older clients; stage the change.' },
          customer_visible: { level: 'low', notes: 'Stronger crypto; transparent to modern clients.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Per-service migration + validation.' },
          steps: [
            'For each EXTERNAL-protectionLevel key over federal data, migrate to SOFTWARE (CMVP #5104) or HSM (CMVP #3490), or attach the EKM module\'s active CMVP certificate.',
            'For each weak SSL policy, set min_tls_version=TLS_1_2 and profile=MODERN/RESTRICTED.',
            'For app-layer crypto, build with BoringCrypto in FIPS mode and record the cert number.',
          ],
          references: [
            { title: 'GCP FIPS 140 validated', url: 'https://cloud.google.com/security/compliance/fips-140-2-validated' },
            { title: 'Cloud KMS protection levels', url: 'https://cloud.google.com/kms/docs/algorithms#protection_levels' },
          ],
        },
        {
          approach: 'If the module in use IS validated but the collector cannot see it (app-layer / subprocessor), attach the CMVP attestation rather than changing infrastructure.',
          mechanism: 'process',
          owner_team: 'Compliance',
          cost_impact: { level: 'none', notes: 'Documentation only.' },
          availability_impact: { level: 'none', notes: 'No change.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Collect attestations.' },
          steps: [
            'Identify the module performing the flagged crypto (app TLS library, subprocessor service).',
            'Obtain its active CMVP certificate number and validation scope.',
            'Record it against the flagged resource in the UCM-CSX-CMD inventory.',
          ],
        },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['sc-13', 'sc-12', 'sc-8', 'ia-7'],
    note: `Impact level read from CLOUD_EVIDENCE_IMPACT_LEVEL='${process.env.CLOUD_EVIDENCE_IMPACT_LEVEL ?? '(unset, default moderate)'}'. UCM-CSX-UVM key word at this level: ${uvmKeyWord}.`,
  });

  const findings = [cmdFinding, catFinding, uvmFinding];

  const thirdParty = detectThirdParty({});
  return {
    provider: 'gcp',
    project_id: ctx.project,
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}
