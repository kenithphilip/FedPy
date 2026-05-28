/**
 * AWS Using-Cryptographic-Modules collector — UCM family (UCM-CSX-CMD / -CAT / -UVM).
 *
 * UCM is about FIPS 140-2/140-3 CMVP-validated cryptographic modules protecting
 * federal customer data. This collector is STRICTLY READ-ONLY: it only
 * Describe/List/Get-s KMS, ACM, ELBv2, and CloudFront resources, maps each
 * data-protecting crypto service to a CMVP-validated module via a small static
 * reference table, and grades against the run's impact level.
 *
 * Three requirements, one collector:
 *   - UCM-CSX-CMD (MUST): document which modules protect federal customer data
 *     and whether each is CMVP-validated. Proxy = build a CMVP-labeled inventory
 *     of cloud-native crypto (KMS origin/spec, ACM key algorithms, TLS policies).
 *   - UCM-CSX-CAT (SHOULD): default agency-tenant config selects validated-module
 *     crypto. Proxy = no key/cert/TLS-policy defaults are pinned to a
 *     non-validated module (EXTERNAL key store, non-FIPS TLS policy).
 *   - UCM-CSX-UVM (Low MAY / Moderate SHOULD / High MUST): actually USE modules
 *     with ACTIVE CMVP validations. The pass criterion + finding severity scale
 *     by the run's impact level (see severityForUcm / keyWordForUcm).
 *
 * Impact level is read from process.env.CLOUD_EVIDENCE_IMPACT_LEVEL (default
 * 'moderate') because CollectorContext doesn't carry the level today.
 *
 * Every external call is wrapped with diagnoseAwsError on failure, naming the
 * exact IAM action the runner must be granted.
 */
import { ListKeysCommand, DescribeKeyCommand, GetKeyPolicyCommand } from '@aws-sdk/client-kms';
import { ListCertificatesCommand, DescribeCertificateCommand } from '@aws-sdk/client-acm';
import { DescribeLoadBalancersCommand, DescribeListenersCommand, DescribeSSLPoliciesCommand } from '@aws-sdk/client-elastic-load-balancing-v2';
import { ListDistributionsCommand, GetDistributionCommand } from '@aws-sdk/client-cloudfront';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier } from '../../core/envelope.ts';
import type { Severity, KeyWord, ImpactTier } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';
import { classifyError, diagnoseAwsError } from '../../core/error-diagnostics.ts';

/** Hard cap on pagination loops so a buggy/looping marker can never hang collection. */
const MAX_PAGINATION_ITERATIONS = 1000;

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

/**
 * Push a warning only when an error is a permission/throttle/network problem.
 * "Not configured"/"not found" errors (no certs, no key policy, etc.) are
 * expected and stay silent so the warnings list reflects real action items.
 */
function warnIfActionable(warnings: string[], err: unknown, source: string, requiredAction: string): void {
  const klass = classifyError(err);
  if (klass === 'not_found' || klass === 'not_enabled') return;
  warnings.push(diagnoseAwsError(err, source, requiredAction));
}

// =====================================================================
// CMVP reference table.
// Cert numbers cited from cloud-evidence/docs/analysis/pva-scg-ucm.md, which
// in turn grounds them against the NIST CMVP search + AWS/GCP FIPS pages.
// This is a *static* lookup, not a live CMVP query — review on each CMVP
// historical-list change (see hsm1.medium note below).
// =====================================================================
export interface CmvpEntry {
  /** Module/library name as it appears (loosely) in CMVP. */
  module: string;
  /** CMVP certificate number (string; some are series like '4884'). */
  cert: string;
  /** FIPS standard the validation is against. */
  standard: 'FIPS 140-2' | 'FIPS 140-3';
  /** Security level (1-4). */
  level: 1 | 2 | 3 | 4;
  /** Is the validation currently ACTIVE (vs historical/revoked)? */
  active: boolean;
  /** Operator-facing note (caveats, migration guidance). */
  note?: string;
}

export const AWS_CMVP_REFERENCE: Record<string, CmvpEntry> = {
  // AWS KMS HSM backing all AWS_KMS-origin keys.
  kms_hsm: {
    module: 'AWS Key Management Service HSM',
    cert: '4884',
    standard: 'FIPS 140-3',
    level: 3,
    active: true,
    note: 'Backs all Origin=AWS_KMS keys. The hsm1.medium HSM class moved to the CMVP historical list on 2026-01-04; "active validation" now means the hsm2m.medium stream. Treat as an update-stream per FedRAMP allowance.',
  },
  // AWS-LC FIPS module backing the ELB/CloudFront *-FIPS-* TLS policies.
  aws_lc_fips: {
    module: 'AWS-LC FIPS module',
    cert: '4759',
    standard: 'FIPS 140-3',
    level: 1,
    active: true,
    note: 'Backs the ELB/ALB/NLB *-FIPS-* SSL policies and FIPS endpoints. Non-FIPS TLS policies are NOT validated-module-backed.',
  },
  // AWS CloudHSM (used when a key Origin = AWS_CLOUDHSM custom key store).
  cloudhsm: {
    module: 'AWS CloudHSM (Marvell LiquidSecurity)',
    cert: '4218',
    standard: 'FIPS 140-2',
    level: 3,
    active: true,
    note: 'Backs custom key stores with CustomKeyStoreType=AWS_CLOUDHSM. Validated, but requires the operator confirm the cluster firmware version is the validated one.',
  },
};

// =====================================================================
// Level-aware obligation model for UCM-CSX-UVM.
//   Low      -> MAY     -> a failing finding is informational ('info').
//   Moderate -> SHOULD  -> a failing finding is 'medium'.
//   High     -> MUST    -> a failing finding is 'high'.
// Exported so the test suite can assert the mapping without live calls.
// =====================================================================
export function impactLevelFromEnv(): ImpactTier {
  const raw = (process.env.CLOUD_EVIDENCE_IMPACT_LEVEL ?? 'moderate').toLowerCase().trim();
  if (raw === 'low') return 'low';
  if (raw === 'high') return 'high';
  return 'moderate';
}

/** The RFC-2119 key word UCM-CSX-UVM carries at a given impact level. */
export function keyWordForUcm(level: ImpactTier): KeyWord {
  if (level === 'low') return 'MAY';
  if (level === 'high') return 'MUST';
  return 'SHOULD';
}

/** Severity a FAILING UCM-CSX-UVM finding should carry at a given impact level. */
export function severityForUcm(level: ImpactTier): Severity {
  if (level === 'low') return 'info';   // MAY: never punish, report coverage only
  if (level === 'high') return 'high';  // MUST
  return 'medium';                       // SHOULD
}

interface Ctx { region: string; auth: aws.AwsAuth; account: string | null; }
async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? 'us-east-1';
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) { try { account = (await aws.whoAmI(auth)).account; } catch { /* */ } }
  return { region, auth, account };
}

/** Map a KMS key Origin to its CMVP backing (or null = needs manual proof). */
function cmvpForKmsOrigin(origin: string | undefined): CmvpEntry | null {
  if (origin === 'AWS_KMS') return AWS_CMVP_REFERENCE.kms_hsm!;
  if (origin === 'AWS_CLOUDHSM') return AWS_CMVP_REFERENCE.cloudhsm!;
  return null; // EXTERNAL / EXTERNAL_KEY_STORE => operator must attach CMVP proof.
}

/** True if an ELB/CloudFront TLS policy name maps to the AWS-LC FIPS module. */
function isFipsTlsPolicy(name: string | undefined): boolean {
  return !!name && /-FIPS-/i.test(name);
}

export async function collectUcm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const level = impactLevelFromEnv();
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ---------------------------------------------------------------
  // 1. KMS keys: origin + spec + key-policy presence.
  // ---------------------------------------------------------------
  interface KmsKeyRecord {
    KeyId: string;
    KeyManager: string;
    KeyState: string;
    KeySpec?: string;
    Origin?: string;
    CustomKeyStoreId?: string;
    cmvpModule: string | null;
    cmvpCert: string | null;
    cmvpActive: boolean | null;
    hasKeyPolicy: boolean;
  }
  const kmsKeys: KmsKeyRecord[] = [];
  try {
    const kms = aws.kms(ctx.auth);
    let marker: string | undefined;
    let iter = 0;
    do {
      const r = await kms.send(new ListKeysCommand({ Marker: marker, Limit: 100 }));
      for (const k of r.Keys ?? []) {
        if (!k.KeyId) continue;
        try {
          const d = await kms.send(new DescribeKeyCommand({ KeyId: k.KeyId }));
          const md = d.KeyMetadata;
          if (!md) continue;
          // Skip AWS-managed keys for inventory clarity? No — they are also KMS-HSM
          // backed and protect data, so include them. Mark the manager.
          const origin = md.Origin;
          const cmvp = cmvpForKmsOrigin(origin);
          let hasKeyPolicy = false;
          try {
            const pol = await kms.send(new GetKeyPolicyCommand({ KeyId: k.KeyId, PolicyName: 'default' }));
            hasKeyPolicy = !!pol.Policy;
          } catch (e) {
            warnIfActionable(warnings, e, `kms.GetKeyPolicy ${k.KeyId}`, 'kms:GetKeyPolicy');
          }
          kmsKeys.push({
            KeyId: k.KeyId,
            KeyManager: md.KeyManager ?? '',
            KeyState: md.KeyState ?? '',
            KeySpec: md.KeySpec,
            Origin: origin,
            CustomKeyStoreId: md.CustomKeyStoreId,
            cmvpModule: cmvp?.module ?? null,
            cmvpCert: cmvp?.cert ?? null,
            cmvpActive: cmvp ? cmvp.active : null,
            hasKeyPolicy,
          });
        } catch (e) { warnIfActionable(warnings, e, `kms.DescribeKey ${k.KeyId}`, 'kms:DescribeKey'); }
      }
      const next = r.NextMarker;
      marker = next && next !== marker ? next : undefined;
    } while (marker && ++iter < MAX_PAGINATION_ITERATIONS);
    evidence.push(ev('kms.crypto_module_inventory', kmsKeys));
  } catch (e) { warnIfActionable(warnings, e, 'kms.ListKeys', 'kms:ListKeys'); }

  const kmsExternalKeys = kmsKeys.filter((k) => k.cmvpModule === null && k.KeyState !== 'PendingDeletion');
  const kmsValidatedKeys = kmsKeys.filter((k) => k.cmvpModule !== null);

  // ---------------------------------------------------------------
  // 2. ACM certificates: key algorithm inventory.
  // ---------------------------------------------------------------
  interface CertRecord { Arn: string; DomainName: string; KeyAlgorithm?: string; Status?: string; InUse: boolean; approvedAlgorithm: boolean; }
  const certs: CertRecord[] = [];
  // Approved (CMVP-implementable) public-key algorithms for TLS.
  const APPROVED_CERT_ALGS = /^(RSA_2048|RSA_3072|RSA_4096|EC_prime256v1|EC_secp384r1|EC_secp521r1)$/i;
  try {
    const a = aws.acm(ctx.auth);
    let tok: string | undefined;
    let iter = 0;
    do {
      const r = await a.send(new ListCertificatesCommand({ NextToken: tok, MaxItems: 100 }));
      for (const cert of r.CertificateSummaryList ?? []) {
        if (!cert.CertificateArn) continue;
        try {
          const d = await a.send(new DescribeCertificateCommand({ CertificateArn: cert.CertificateArn }));
          const c2 = d.Certificate;
          const alg = c2?.KeyAlgorithm;
          certs.push({
            Arn: cert.CertificateArn,
            DomainName: c2?.DomainName ?? '',
            KeyAlgorithm: alg,
            Status: c2?.Status,
            InUse: (c2?.InUseBy?.length ?? 0) > 0,
            approvedAlgorithm: !!alg && APPROVED_CERT_ALGS.test(alg),
          });
        } catch (e) { warnIfActionable(warnings, e, `acm.DescribeCertificate ${cert.CertificateArn}`, 'acm:DescribeCertificate'); }
      }
      const next = r.NextToken;
      tok = next && next !== tok ? next : undefined;
    } while (tok && ++iter < MAX_PAGINATION_ITERATIONS);
    evidence.push(ev('acm.cert_algorithm_inventory', certs.map((c2) => ({ DomainName: c2.DomainName, KeyAlgorithm: c2.KeyAlgorithm, Status: c2.Status, InUse: c2.InUse, approved: c2.approvedAlgorithm }))));
  } catch (e) { warnIfActionable(warnings, e, 'acm.ListCertificates', 'acm:ListCertificates'); }

  const certsWithWeakAlgorithm = certs.filter((c2) => c2.KeyAlgorithm && !c2.approvedAlgorithm);

  // ---------------------------------------------------------------
  // 3. ELBv2 listeners: TLS (SSL) policies → FIPS or not.
  // ---------------------------------------------------------------
  interface ListenerRecord { LoadBalancer: string; ListenerArn: string; Protocol?: string; SslPolicy?: string; isFips: boolean; }
  const listeners: ListenerRecord[] = [];
  let fipsCapablePolicyAvailable = false;
  try {
    const elb = aws.elbv2(ctx.auth);
    // Is at least one FIPS SSL policy *available* in this region? ("when available")
    try {
      const sp = await elb.send(new DescribeSSLPoliciesCommand({}));
      fipsCapablePolicyAvailable = (sp.SslPolicies ?? []).some((p) => isFipsTlsPolicy(p.Name));
    } catch (e) { warnIfActionable(warnings, e, 'elbv2.DescribeSSLPolicies', 'elasticloadbalancing:DescribeSSLPolicies'); }

    let lbMarker: string | undefined;
    let lbIter = 0;
    do {
      const lbs = await elb.send(new DescribeLoadBalancersCommand({ Marker: lbMarker, PageSize: 100 }));
      for (const lb of lbs.LoadBalancers ?? []) {
        if (!lb.LoadBalancerArn) continue;
        try {
          const ls = await elb.send(new DescribeListenersCommand({ LoadBalancerArn: lb.LoadBalancerArn }));
          for (const l of ls.Listeners ?? []) {
            if (l.Protocol !== 'HTTPS' && l.Protocol !== 'TLS') continue; // only TLS-terminating listeners have an SslPolicy
            listeners.push({
              LoadBalancer: lb.LoadBalancerName ?? lb.LoadBalancerArn,
              ListenerArn: l.ListenerArn ?? '',
              Protocol: l.Protocol,
              SslPolicy: l.SslPolicy,
              isFips: isFipsTlsPolicy(l.SslPolicy),
            });
          }
        } catch (e) { warnIfActionable(warnings, e, `elbv2.DescribeListeners ${lb.LoadBalancerName}`, 'elasticloadbalancing:DescribeListeners'); }
      }
      const next = lbs.NextMarker;
      lbMarker = next && next !== lbMarker ? next : undefined;
    } while (lbMarker && ++lbIter < MAX_PAGINATION_ITERATIONS);
    evidence.push(ev('elbv2.tls_policy_inventory', { fips_policy_available: fipsCapablePolicyAvailable, listeners }));
  } catch (e) { warnIfActionable(warnings, e, 'elbv2.DescribeLoadBalancers', 'elasticloadbalancing:DescribeLoadBalancers'); }

  const tlsListenersWithoutFips = listeners.filter((l) => !l.isFips);

  // ---------------------------------------------------------------
  // 4. CloudFront distributions: viewer-side minimum TLS / security policy.
  //    CloudFront does not expose a FIPS policy name, but the minimum
  //    protocol version is the observable signal of modern-TLS posture.
  // ---------------------------------------------------------------
  interface CfRecord { Id: string; DomainName: string; MinimumProtocolVersion?: string; modernTls: boolean; }
  const cfDistributions: CfRecord[] = [];
  try {
    const cf = aws.cloudfront(ctx.auth);
    let cfMarker: string | undefined;
    let cfIter = 0;
    do {
      const r = await cf.send(new ListDistributionsCommand({ Marker: cfMarker }));
      for (const d of r.DistributionList?.Items ?? []) {
        if (!d.Id) continue;
        try {
          const det = await cf.send(new GetDistributionCommand({ Id: d.Id }));
          const vc = det.Distribution?.DistributionConfig?.ViewerCertificate;
          const minProto = vc?.MinimumProtocolVersion;
          cfDistributions.push({
            Id: d.Id,
            DomainName: d.DomainName ?? '',
            MinimumProtocolVersion: minProto,
            modernTls: !!minProto && /TLSv1\.2|TLSv1\.3/i.test(minProto),
          });
        } catch (e) { warnIfActionable(warnings, e, `cloudfront.GetDistribution ${d.Id}`, 'cloudfront:GetDistribution'); }
      }
      const next = r.DistributionList?.NextMarker;
      cfMarker = next && next !== cfMarker ? next : undefined;
    } while (cfMarker && ++cfIter < MAX_PAGINATION_ITERATIONS);
    evidence.push(ev('cloudfront.tls_inventory', cfDistributions));
  } catch (e) { warnIfActionable(warnings, e, 'cloudfront.ListDistributions', 'cloudfront:ListDistributions'); }

  // ---------------------------------------------------------------
  // Alternative satisfiers (UCM-wide).
  // ---------------------------------------------------------------
  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'AWS CloudHSM custom key store (FIPS 140-2 Level 3, CMVP cert #4218)',
      description: 'Federal-data crypto operations served by a CloudHSM-backed KMS custom key store instead of the default AWS KMS HSM. Still CMVP-validated; satisfies UVM as an alternative module.',
      evidence_required: ['kms:DescribeCustomKeyStores output', 'CloudHSM cluster firmware version vs the CMVP-validated version', 'Mapping of federal-data keys to the custom key store'],
      detected: kmsKeys.some((k) => k.Origin === 'AWS_CLOUDHSM'),
      detection_signals: kmsKeys.filter((k) => k.Origin === 'AWS_CLOUDHSM').map((k) => `KMS key ${k.KeyId} Origin=AWS_CLOUDHSM`),
    },
    {
      via: 'External KMS / dedicated HSM vendor (Thales, Entrust, Fortanix) with its own CMVP cert',
      description: 'EXTERNAL / EXTERNAL_KEY_STORE-origin keys are backed by an operator-supplied module. Validated iff the operator attaches that module\'s active CMVP certificate.',
      evidence_required: ['Vendor module CMVP certificate number + active status', 'kms:DescribeCustomKeyStores (XKS) output', 'Attestation that federal-data keys route to that module'],
      detected: kmsKeys.some((k) => k.cmvpModule === null),
      detection_signals: kmsExternalKeys.map((k) => `KMS key ${k.KeyId} Origin=${k.Origin ?? 'EXTERNAL'} (needs CMVP proof)`),
    },
    {
      via: 'Subprocessor CMVP inheritance',
      description: 'Federal-data crypto handled by a subprocessor whose modules are CMVP-validated; the CSP inherits that validation via attestation. Signal lives in core/subprocessors-sheet.ts.',
      evidence_required: ['Subprocessor CMVP attestation in the subprocessors sheet', 'Cert number + active status', 'Scope: which federal-data flows the subprocessor protects'],
      detected: false,
      detection_signals: [],
    },
    {
      via: 'App-layer FIPS provider (AWS-LC FIPS / OpenSSL 3 FIPS module, FIPS-enabled GKE/AMIs)',
      description: 'When the app terminates TLS or encrypts at rest itself, the build-time FIPS provider is the validated module. Not fully cloud-API-visible — supply build flags as artifact.',
      evidence_required: ['Build flags / Dockerfile showing FIPS provider', 'Module CMVP cert', 'Runtime FIPS-mode assertion (e.g. openssl fipsinstall log)'],
      detected: false,
      detection_signals: [],
    },
  ];

  // ---------------------------------------------------------------
  // Findings.
  // ---------------------------------------------------------------
  const nistControls = ['sc-13', 'sc-12', 'sc-8'];

  // ---- UCM-CSX-CMD: documentation / inventory proxy (always MUST) ----
  const inventoryBuilt = kmsKeys.length + certs.length + listeners.length + cfDistributions.length > 0;
  const cmdFinding = finding({
    rule: 'aws.ucm.cmd.crypto_module_inventory_built',
    passed: inventoryBuilt,
    severity: 'high',
    applicable_key_word: 'MUST',
    current: {
      summary: inventoryBuilt
        ? `Built a CMVP-labeled inventory: ${kmsKeys.length} KMS key(s) (${kmsValidatedKeys.length} validated-module-backed, ${kmsExternalKeys.length} EXTERNAL/manual), ${certs.length} ACM cert(s), ${listeners.length} TLS listener(s), ${cfDistributions.length} CloudFront distribution(s).`
        : 'No cloud-native cryptographic modules observed via KMS/ACM/ELB/CloudFront. Either the runner lacks read permission, no crypto services are in this region/account, or federal-data crypto lives entirely in the app layer / a subprocessor (document those separately).',
      observations: {
        kms: kmsKeys.map((k) => ({ KeyId: k.KeyId, KeyManager: k.KeyManager, Origin: k.Origin, KeySpec: k.KeySpec, cmvp_module: k.cmvpModule, cmvp_cert: k.cmvpCert, cmvp_active: k.cmvpActive })),
        acm: certs.map((c2) => ({ domain: c2.DomainName, alg: c2.KeyAlgorithm, approved: c2.approvedAlgorithm })),
        elb_tls: listeners.map((l) => ({ lb: l.LoadBalancer, policy: l.SslPolicy, fips: l.isFips })),
        cloudfront: cfDistributions.map((d) => ({ id: d.Id, min_tls: d.MinimumProtocolVersion })),
        cmvp_reference_table: AWS_CMVP_REFERENCE,
      },
    },
    target: {
      summary: 'A documented inventory maps every cryptographic service that protects federal customer data to its backing module and CMVP status {validated | update-stream | not-validated}.',
      rationale: 'UCM-CSX-CMD MUST. NIST SC-13/SC-12: you cannot assert validated cryptography without first enumerating which module performs each cryptographic function over federal data.',
    },
    gap: inventoryBuilt ? undefined : {
      description: 'No crypto-module inventory could be built from cloud-native reads. Coverage may be incomplete (app-layer + subprocessor modules are not cloud-API-visible).',
      affected_resources: [{ type: 'aws_kms_key', identifier: 'none', attributes: {} }],
    },
    remediation: inventoryBuilt ? undefined : {
      summary: 'Confirm read permissions, then document app-layer and subprocessor modules to complete the inventory.',
      options: [
        {
          approach: 'Grant the runner the UCM read actions and re-run; then hand-author the app-layer/subprocessor module rows.',
          mechanism: 'terraform',  // IaC delivery
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'none', notes: 'Read-only.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Inventory authoring.' },
          steps: [
            'Attach kms:ListKeys/DescribeKey/GetKeyPolicy, acm:ListCertificates/DescribeCertificate, elasticloadbalancing:DescribeLoadBalancers/DescribeListeners/DescribeSSLPolicies, cloudfront:ListDistributions/GetDistribution.',
            'Re-run the collector to populate cloud-native modules.',
            'Add rows for app-layer crypto (TLS termination libraries, at-rest encryption) and subprocessor modules with their CMVP cert numbers.',
          ],
          references: [{ title: 'NIST CMVP search', url: 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search' }],
        },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: nistControls,
  });

  // ---- UCM-CSX-CAT: default-tenant config selects validated-module crypto (SHOULD) ----
  // Proxy for "defaults": no in-scope crypto default resolves to a non-validated module.
  // - KMS: any EXTERNAL-origin key would default federal data to a non-validated module.
  // - ELB: TLS listeners default to a non-FIPS policy while a FIPS policy IS available.
  // - ACM: any cert uses a non-approved key algorithm.
  const catNonFipsListenersWhenAvailable = fipsCapablePolicyAvailable ? tlsListenersWithoutFips : [];
  const catPasses = kmsExternalKeys.length === 0 && catNonFipsListenersWhenAvailable.length === 0 && certsWithWeakAlgorithm.length === 0;
  const catFinding = finding({
    rule: 'aws.ucm.cat.agency_tenant_defaults_validated',
    passed: catPasses,
    severity: 'medium',
    applicable_key_word: 'SHOULD',
    current: {
      summary: catPasses
        ? `Default crypto selections resolve to validated modules where available: 0 EXTERNAL-origin KMS keys, ${fipsCapablePolicyAvailable ? `${tlsListenersWithoutFips.length} non-FIPS TLS listener(s) (FIPS policy ${fipsCapablePolicyAvailable ? 'available' : 'unavailable'})` : 'FIPS TLS policy not available in region (exempt under "when available")'}, ${certsWithWeakAlgorithm.length} weak cert algorithm(s).`
        : `Some defaults select non-validated-module crypto: ${kmsExternalKeys.length} EXTERNAL-origin KMS key(s), ${catNonFipsListenersWhenAvailable.length} non-FIPS TLS listener(s) while a FIPS policy is available, ${certsWithWeakAlgorithm.length} cert(s) with a non-approved key algorithm.`,
      observations: {
        external_origin_keys: kmsExternalKeys.map((k) => ({ KeyId: k.KeyId, Origin: k.Origin })),
        non_fips_listeners: catNonFipsListenersWhenAvailable.map((l) => ({ lb: l.LoadBalancer, policy: l.SslPolicy })),
        fips_policy_available: fipsCapablePolicyAvailable,
        weak_cert_algorithms: certsWithWeakAlgorithm.map((c2) => ({ domain: c2.DomainName, alg: c2.KeyAlgorithm })),
      },
    },
    target: {
      summary: 'When provisioning agency tenants, defaults select CMVP-validated-module-backed crypto wherever such a module is available (validated KMS HSM keys, *-FIPS-* TLS policies, approved cert algorithms).',
      rationale: 'UCM-CSX-CAT SHOULD. NIST SC-13/CM-6: secure-by-default crypto for federal tenants. "When available" exempts regions/services without a FIPS option.',
    },
    gap: catPasses ? undefined : {
      description: 'Default-tenant crypto can land federal data on a non-validated module even though a validated option is available.',
      affected_resources: [
        ...kmsExternalKeys.map<AffectedResource>((k) => ({ type: 'aws_kms_key', identifier: k.KeyId, name: k.KeyId, attributes: { Origin: k.Origin } })),
        ...catNonFipsListenersWhenAvailable.map<AffectedResource>((l) => ({ type: 'aws_lb_listener', identifier: l.ListenerArn, name: l.LoadBalancer, attributes: { ssl_policy: l.SslPolicy } })),
        ...certsWithWeakAlgorithm.map<AffectedResource>((c2) => ({ type: 'aws_acm_certificate', identifier: c2.Arn, name: c2.DomainName, attributes: { key_algorithm: c2.KeyAlgorithm } })),
      ],
    },
    remediation: catPasses ? undefined : {
      summary: 'Pin validated-module crypto in the tenant-provisioning baseline (default KMS to AWS_KMS/CloudHSM origin, default TLS listeners to a *-FIPS-* policy, issue certs with approved algorithms).',
      options: [
        {
          approach: 'Set FIPS SSL policy + KMS HSM defaults in the landing-zone / provisioning IaC.',
          mechanism: 'terraform',  // IaC delivery
          owner_team: 'Platform',
          cost_impact: { level: 'low', notes: 'No incremental cost for FIPS policies; CloudHSM custom key stores carry HSM cost.' },
          availability_impact: { level: 'medium', notes: 'Older clients may not negotiate FIPS-only cipher suites; validate against your client matrix.' },
          customer_visible: { level: 'low', notes: 'Stricter TLS for agency tenants.' },
          effort_estimate: { magnitude: 'days', notes: 'Baseline change + tenant rollout.' },
          steps: [
            'In the tenant ALB/NLB module, set ssl_policy to a *-FIPS-* policy (e.g. ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04).',
            'Default tenant KMS keys to Origin=AWS_KMS (or a CloudHSM custom key store); avoid EXTERNAL unless the external module has an active CMVP cert.',
            'Request ACM certs with RSA_2048+ or EC_secp384r1.',
          ],
          example_code: `resource "aws_lb_listener" "agency_https" {
  load_balancer_arn = aws_lb.agency.arn
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04"  # AWS-LC FIPS (CMVP #4759)
  certificate_arn   = aws_acm_certificate.agency.arn
}`,
          references: [{ title: 'ELB FIPS security policies', url: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html' }],
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
  // What fails depends on the level:
  //   Low (MAY)      -> never fail; report coverage only.
  //   Moderate(SHOULD)-> fail if validated modules are AVAILABLE but not used:
  //                      EXTERNAL keys w/o proof, or non-FIPS TLS while FIPS available.
  //   High (MUST)    -> fail if ANY in-scope service uses a non-validated/inactive module:
  //                      any EXTERNAL key, any non-FIPS TLS listener, any weak cert alg.
  const inactiveValidatedKeys = kmsKeys.filter((k) => k.cmvpActive === false);
  let uvmViolations: AffectedResource[] = [];
  if (level === 'high') {
    uvmViolations = [
      ...kmsExternalKeys.map<AffectedResource>((k) => ({ type: 'aws_kms_key', identifier: k.KeyId, name: k.KeyId, attributes: { Origin: k.Origin, reason: 'non-validated module (needs CMVP proof)' } })),
      ...inactiveValidatedKeys.map<AffectedResource>((k) => ({ type: 'aws_kms_key', identifier: k.KeyId, name: k.KeyId, attributes: { cmvp_cert: k.cmvpCert, reason: 'CMVP validation inactive' } })),
      ...tlsListenersWithoutFips.map<AffectedResource>((l) => ({ type: 'aws_lb_listener', identifier: l.ListenerArn, name: l.LoadBalancer, attributes: { ssl_policy: l.SslPolicy, reason: 'non-FIPS TLS policy' } })),
      ...certsWithWeakAlgorithm.map<AffectedResource>((c2) => ({ type: 'aws_acm_certificate', identifier: c2.Arn, name: c2.DomainName, attributes: { key_algorithm: c2.KeyAlgorithm, reason: 'non-approved algorithm' } })),
    ];
  } else if (level === 'moderate') {
    uvmViolations = [
      ...kmsExternalKeys.map<AffectedResource>((k) => ({ type: 'aws_kms_key', identifier: k.KeyId, name: k.KeyId, attributes: { Origin: k.Origin, reason: 'validated KMS HSM available but EXTERNAL used without CMVP proof' } })),
      ...(fipsCapablePolicyAvailable ? tlsListenersWithoutFips : []).map<AffectedResource>((l) => ({ type: 'aws_lb_listener', identifier: l.ListenerArn, name: l.LoadBalancer, attributes: { ssl_policy: l.SslPolicy, reason: 'FIPS TLS policy available but not used' } })),
    ];
  } // low: leave empty (MAY)

  const uvmPasses = level === 'low' ? true : uvmViolations.length === 0;
  // Coverage stats (always reported, the primary signal at Low).
  const validatedCryptoCount = kmsValidatedKeys.length + listeners.filter((l) => l.isFips).length + certs.filter((c2) => c2.approvedAlgorithm).length;
  const totalCryptoCount = kmsKeys.filter((k) => k.KeyState !== 'PendingDeletion').length + listeners.length + certs.filter((c2) => !!c2.KeyAlgorithm).length;
  const coveragePct = totalCryptoCount === 0 ? null : Math.round((validatedCryptoCount / totalCryptoCount) * 100);

  const uvmFinding = finding({
    rule: 'aws.ucm.uvm.uses_validated_cryptographic_modules',
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
        validated_kms_keys: kmsValidatedKeys.map((k) => ({ KeyId: k.KeyId, cert: k.cmvpCert })),
        external_kms_keys: kmsExternalKeys.map((k) => ({ KeyId: k.KeyId, Origin: k.Origin })),
        inactive_validation_keys: inactiveValidatedKeys.map((k) => ({ KeyId: k.KeyId, cert: k.cmvpCert })),
        fips_tls_listeners: listeners.filter((l) => l.isFips).map((l) => l.LoadBalancer),
        non_fips_tls_listeners: tlsListenersWithoutFips.map((l) => ({ lb: l.LoadBalancer, policy: l.SslPolicy })),
        fips_policy_available: fipsCapablePolicyAvailable,
        weak_cert_algorithms: certsWithWeakAlgorithm.map((c2) => ({ domain: c2.DomainName, alg: c2.KeyAlgorithm })),
        cmvp_reference_table: AWS_CMVP_REFERENCE,
      },
    },
    target: {
      summary: level === 'high'
        ? 'Every cryptographic service protecting federal customer data uses a module with an ACTIVE CMVP validation (MUST at High).'
        : level === 'moderate'
          ? 'Where a CMVP-validated module is available, it is used for federal-data crypto (SHOULD at Moderate); exceptions are justified.'
          : 'Validated modules are used where practical (MAY at Low); coverage is reported for awareness, never failed.',
      rationale: `UCM-CSX-UVM is the only UCM requirement with an explicitly published per-level key word (Low MAY / Moderate SHOULD / High MUST). NIST SC-13/SC-12/SC-8. AWS KMS HSM (CMVP #4884) backs AWS_KMS keys; AWS-LC FIPS (CMVP #4759) backs *-FIPS-* TLS policies.`,
    },
    gap: uvmPasses ? undefined : {
      description: `At impact level '${level}', ${uvmViolations.length} cryptographic service(s) do not use an active CMVP-validated module. A failing ${uvmKeyWord} is reported at '${uvmSeverity}' severity.`,
      affected_resources: uvmViolations,
    },
    remediation: uvmPasses ? undefined : {
      summary: 'Move federal-data crypto onto validated modules: AWS_KMS/CloudHSM-origin keys, *-FIPS-* TLS policies, approved cert algorithms — or attach CMVP proof for the external/app-layer module in use.',
      options: [
        {
          approach: 'Switch TLS listeners to a FIPS policy and re-key federal data with an AWS_KMS-origin CMK.',
          mechanism: 'terraform',  // IaC delivery
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Re-encryption KMS calls; CloudHSM cost only if using a custom key store.' },
          availability_impact: { level: 'medium', notes: 'Re-keying and FIPS-only cipher suites can affect older clients; stage the change.' },
          customer_visible: { level: 'low', notes: 'Stronger TLS; transparent to modern clients.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Per-service migration + validation.' },
          steps: [
            'For each non-FIPS TLS listener, set ssl_policy to a *-FIPS-* policy (AWS-LC FIPS, CMVP #4759).',
            'For each EXTERNAL-origin key over federal data, either migrate to an AWS_KMS-origin key (CMVP #4884) / CloudHSM custom key store (CMVP #4218), or attach the external module\'s active CMVP certificate.',
            'Re-issue weak-algorithm certs with RSA_2048+ / EC_secp384r1.',
            'For app-layer crypto, build with a FIPS provider and record the cert number.',
          ],
          references: [
            { title: 'AWS KMS FIPS 140-3', url: 'https://docs.aws.amazon.com/kms/latest/developerguide/fips-validation.html' },
            { title: 'ELB FIPS security policies', url: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html' },
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
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}
