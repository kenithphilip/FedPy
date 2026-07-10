/**
 * AWS secrets-management collector — KSI-SVC-ASM.
 *
 * Three orthogonal evidence layers (do not conflate):
 *   1. Secrets store exists + populated.
 *   2. Rotation IS configured per secret.
 *   3. Rotation ACTUALLY HAPPENS recently (LastRotatedDate within window).
 *
 * Plus parallel: KMS CMK rotation enabled + ACM cert renewal status.
 */
import { ListSecretsCommand, DescribeSecretCommand } from '@aws-sdk/client-secrets-manager';
import { ListKeysCommand, DescribeKeyCommand, GetKeyRotationStatusCommand } from '@aws-sdk/client-kms';
import { ListCertificatesCommand, DescribeCertificateCommand } from '@aws-sdk/client-acm';
import { DescribeParametersCommand } from '@aws-sdk/client-ssm';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';
import { diagnoseAwsError } from '../../core/error-diagnostics.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

interface Ctx { region: string; auth: aws.AwsAuth; account: string | null; }
async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? 'us-east-1';
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) { try { account = (await aws.whoAmI(auth)).account; } catch { /* */ } }
  return { region, auth, account };
}

const STALE_SECRET_DAYS = 90;
const STALE_ROTATION_BUFFER_DAYS = 7; // tolerate rotation period + 7 days

export async function collectSvcAsm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ---- Secrets Manager ----
  interface SecretRecord {
    Name: string;
    ARN: string;
    RotationEnabled: boolean;
    RotationRulesAutomaticallyAfterDays?: number;
    LastRotatedDate?: Date;
    LastChangedDate?: Date;
    DaysSinceLastRotation?: number;
    rotationStale: boolean;
  }
  const secrets: SecretRecord[] = [];
  let totalSecrets = 0;
  let secretsCollected = false;
  try {
    const sm = aws.secretsmanager(ctx.auth);
    let tok: string | undefined;
    do {
      const r = await sm.send(new ListSecretsCommand({ NextToken: tok, MaxResults: 100 }));
      for (const s of r.SecretList ?? []) {
        if (!s.ARN || !s.Name) continue;
        totalSecrets++;
        try {
          const d = await sm.send(new DescribeSecretCommand({ SecretId: s.ARN }));
          const rotPeriod = d.RotationRules?.AutomaticallyAfterDays;
          const last = d.LastRotatedDate;
          const daysSince = last ? Math.floor((Date.now() - last.getTime()) / 86400000) : undefined;
          const rotationStale = !!(d.RotationEnabled && rotPeriod && daysSince !== undefined && daysSince > rotPeriod + STALE_ROTATION_BUFFER_DAYS);
          secrets.push({
            Name: s.Name,
            ARN: s.ARN,
            RotationEnabled: !!d.RotationEnabled,
            RotationRulesAutomaticallyAfterDays: rotPeriod,
            LastRotatedDate: last,
            LastChangedDate: d.LastChangedDate,
            DaysSinceLastRotation: daysSince,
            rotationStale,
          });
        } catch (e: any) {
          warnings.push(`DescribeSecret ${s.Name}: ${e.message}`);
        }
      }
      tok = r.NextToken;
    } while (tok);
    secretsCollected = true;
    evidence.push(ev('secretsmanager.secret_inventory', secrets));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'secretsmanager.ListSecrets', 'secretsmanager:ListSecrets')); }

  const rotationConfigured = secrets.filter((s) => s.RotationEnabled);
  const rotationStale = secrets.filter((s) => s.rotationStale);
  const secretsWithoutRotation = secrets.filter((s) => !s.RotationEnabled);

  // ---- SSM Parameter Store SecureStrings ----
  let secureStringParamCount = 0;
  let secureStringsWithDefaultKey = 0;
  let ssmParamsCollected = false;
  try {
    const ssm = aws.ssm(ctx.auth);
    let tok: string | undefined;
    do {
      const r = await ssm.send(new DescribeParametersCommand({
        ParameterFilters: [{ Key: 'Type', Values: ['SecureString'] }],
        NextToken: tok,
        MaxResults: 50,
      }));
      for (const p of r.Parameters ?? []) {
        secureStringParamCount++;
        if (p.KeyId === 'alias/aws/ssm') secureStringsWithDefaultKey++;
      }
      tok = r.NextToken;
    } while (tok);
    ssmParamsCollected = true;
    evidence.push(ev('ssm.securestring_parameters', { total: secureStringParamCount, with_default_key: secureStringsWithDefaultKey }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'ssm.DescribeParameters', 'ssm:DescribeParameters')); }

  // ---- KMS CMKs + rotation ----
  interface KmsKeyRecord { KeyId: string; KeyManager: string; KeyState: string; RotationEnabled: boolean; }
  const kmsKeys: KmsKeyRecord[] = [];
  let customerKeyCount = 0;
  let customerKeysWithoutRotation: string[] = [];
  let kmsCollected = false;
  let kmsRotationReadFailures = 0;
  try {
    const kms = aws.kms(ctx.auth);
    let marker: string | undefined;
    do {
      const r = await kms.send(new ListKeysCommand({ Marker: marker, Limit: 100 }));
      for (const k of r.Keys ?? []) {
        if (!k.KeyId) continue;
        try {
          const d = await kms.send(new DescribeKeyCommand({ KeyId: k.KeyId }));
          const mgr = d.KeyMetadata?.KeyManager ?? '';
          const state = d.KeyMetadata?.KeyState ?? '';
          let rotEnabled = false;
          if (mgr === 'CUSTOMER' && state === 'Enabled') {
            customerKeyCount++;
            try {
              const r2 = await kms.send(new GetKeyRotationStatusCommand({ KeyId: k.KeyId }));
              rotEnabled = !!r2.KeyRotationEnabled;
              if (!rotEnabled) customerKeysWithoutRotation.push(k.KeyId);
            } catch (e: any) {
              // UnsupportedOperationException = asymmetric key (rotation N/A — expected).
              // Anything else is a read failure that must NOT be silently treated as
              // "rotation fine" — count it so the pass is gated.
              const code = e?.name ?? e?.code ?? '';
              if (code !== 'UnsupportedOperationException') {
                kmsRotationReadFailures++;
                warnings.push(diagnoseAwsError(e, `kms.GetKeyRotationStatus ${k.KeyId}`, 'kms:GetKeyRotationStatus'));
              }
            }
          }
          kmsKeys.push({ KeyId: k.KeyId, KeyManager: mgr, KeyState: state, RotationEnabled: rotEnabled });
        } catch (e: any) { warnings.push(diagnoseAwsError(e, `kms.DescribeKey ${k.KeyId}`, 'kms:DescribeKey')); }
      }
      marker = r.NextMarker;
    } while (marker);
    kmsCollected = kmsRotationReadFailures === 0;
    evidence.push(ev('kms.key_inventory', { total_keys: kmsKeys.length, customer_managed: customerKeyCount, customer_without_rotation: customerKeysWithoutRotation, rotation_read_failures: kmsRotationReadFailures }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'kms.ListKeys', 'kms:ListKeys')); }

  // ---- ACM certificates ----
  interface CertRecord { Arn: string; DomainName: string; Status: string; NotAfter?: Date; DaysToExpiry?: number; RenewalStatus?: string; }
  const certs: CertRecord[] = [];
  let acmTotal = 0;
  let certsExpiringSoonNoRenewal: CertRecord[] = [];
  let acmCollected = false;
  let acmReadFailures = 0;
  try {
    const a = aws.acm(ctx.auth);
    let tok: string | undefined;
    do {
      const r = await a.send(new ListCertificatesCommand({ NextToken: tok, MaxItems: 100 }));
      for (const cert of r.CertificateSummaryList ?? []) {
        if (!cert.CertificateArn) continue;
        acmTotal++;
        try {
          const d = await a.send(new DescribeCertificateCommand({ CertificateArn: cert.CertificateArn }));
          const c2 = d.Certificate;
          const days = c2?.NotAfter ? Math.floor((c2.NotAfter.getTime() - Date.now()) / 86400000) : undefined;
          const rec: CertRecord = {
            Arn: cert.CertificateArn,
            DomainName: c2?.DomainName ?? '',
            Status: c2?.Status ?? '',
            NotAfter: c2?.NotAfter,
            DaysToExpiry: days,
            RenewalStatus: c2?.RenewalSummary?.RenewalStatus,
          };
          certs.push(rec);
          if (days !== undefined && days < 30 && rec.RenewalStatus !== 'SUCCESS') certsExpiringSoonNoRenewal.push(rec);
        } catch (e: any) { acmReadFailures++; warnings.push(diagnoseAwsError(e, `acm.DescribeCertificate ${cert.CertificateArn}`, 'acm:DescribeCertificate')); }
      }
      tok = r.NextToken;
    } while (tok);
    acmCollected = acmReadFailures === 0;
    evidence.push(ev('acm.cert_inventory', certs.map((c2) => ({ DomainName: c2.DomainName, Status: c2.Status, DaysToExpiry: c2.DaysToExpiry, RenewalStatus: c2.RenewalStatus }))));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'acm.ListCertificates', 'acm:ListCertificates')); }

  // ---- Alternative satisfiers ----
  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'HashiCorp Vault (dynamic secret engines)',
      description: 'Vault issues short-lived credentials on demand, eliminating long-lived secrets entirely.',
      evidence_required: [
        'Vault config showing dynamic secret engines (AWS, database) with short TTL',
        'Sample audit log entry showing dynamic credential issuance + revocation',
        'List of applications consuming Vault tokens',
      ],
      detected: false,
      detection_signals: [],
    },
    {
      via: 'External Secrets Operator (ESO) bridging from Vault / 1Password / AWS-secrets-manager into K8s',
      description: 'ESO can be the rotation orchestrator. Evidence is the ESO config + sync interval.',
      evidence_required: ['ExternalSecret CRDs in cluster', 'Sync interval config', 'Sample sync event'],
      detected: false,
      detection_signals: [],
    },
  ];

  // ---- Findings ----

  const findings = [
    // L1: Secrets store exists
    finding({
      rule: 'aws.secretsmanager.secrets_store_in_use',
      passed: totalSecrets >= 1 || secureStringParamCount >= 1,
      severity: 'high',
      current: {
        summary: totalSecrets >= 1 || secureStringParamCount >= 1
          ? `Secrets stored: ${totalSecrets} in Secrets Manager, ${secureStringParamCount} SecureString params.`
          : 'No secrets in Secrets Manager or SSM SecureString. Either no secrets exist (rare) or they\'re stored elsewhere (anti-pattern: env vars, hardcoded).',
        observations: { secrets_manager_count: totalSecrets, ssm_securestring_count: secureStringParamCount },
      },
      target: { summary: 'Secrets stored in a managed store (Secrets Manager, Parameter Store SecureString, or external Vault).', rationale: 'NIST IA-5, SC-12. Centralized secret storage is the prerequisite for rotation + access control.' },
      gap: (totalSecrets >= 1 || secureStringParamCount >= 1) ? undefined : {
        description: 'No managed-store secrets found. Verify secrets are not in env vars, source code, or shared docs.',
        affected_resources: [{ type: 'aws_secretsmanager_secret', identifier: 'none', attributes: {} }],
      },
      remediation: (totalSecrets >= 1 || secureStringParamCount >= 1) ? undefined : {
        summary: 'Audit application secrets; migrate to Secrets Manager.',
        options: [{
          approach: 'Create Secrets Manager entries via Terraform; update applications to read them.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Secrets Manager: $0.40/secret/month + per-API charges.' },
          availability_impact: { level: 'medium', notes: 'Application code change required; coordinate deploy.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Per-secret migration.' },
          steps: ['Inventory secrets currently in env/code.', 'Create secrets via Terraform.', 'Update apps to use SDK.', 'Remove from env/code.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ia-5','sc-12'],
    }),

    // L2: Rotation configured. Gate on the fetch having succeeded — else "≥80%
    // configured" is vacuous (an empty list looks compliant).
    finding({
      rule: 'aws.secretsmanager.rotation_configured',
      passed: secretsCollected && (totalSecrets === 0 || (rotationConfigured.length / totalSecrets) >= 0.8),
      severity: 'high',
      current: {
        summary: !secretsCollected
          ? 'Secret rotation status INDETERMINATE — Secrets Manager could not be listed.'
          : totalSecrets === 0
            ? 'No secrets to evaluate rotation on.'
            : `${rotationConfigured.length} of ${totalSecrets} (${Math.round(rotationConfigured.length / totalSecrets * 100)}%) secrets have rotation configured.`,
        observations: { collected: secretsCollected, secrets_with_rotation: rotationConfigured.length, secrets_without_rotation: secretsWithoutRotation.map((s) => s.Name) },
      },
      target: { summary: '≥80% of secrets have RotationEnabled. Remaining are documented exceptions (e.g. partner-issued API keys with vendor-controlled lifecycle).', rationale: 'NIST IA-5(1). Static long-lived secrets accumulate compromise risk.' },
      gap: (secretsCollected && (totalSecrets === 0 || (rotationConfigured.length / totalSecrets) >= 0.8)) ? undefined : {
        description: !secretsCollected
          ? 'Secrets Manager could not be listed (permission/throttle), so rotation coverage cannot be asserted.'
          : 'Secrets without rotation are long-lived; if leaked, full lifetime of the secret is the blast radius.',
        affected_resources: secretsWithoutRotation.length ? secretsWithoutRotation.map<AffectedResource>((s) => ({
          type: 'aws_secretsmanager_secret', identifier: s.ARN, name: s.Name, attributes: { LastChangedDate: s.LastChangedDate },
        })) : [{ type: 'aws_secretsmanager_secret', identifier: 'unread', name: 'secrets:ListSecrets failed' }],
      },
      remediation: (secretsCollected && (totalSecrets === 0 || (rotationConfigured.length / totalSecrets) >= 0.8)) ? undefined : {
        summary: 'Configure rotation Lambda + RotationRules on each secret.',
        options: [{
          approach: 'Attach AWS-managed rotation Lambda for supported secret types (RDS, DocumentDB, Redshift).',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Lambda invocations on rotation interval.' },
          availability_impact: { level: 'medium', notes: 'First rotation may cause brief downtime for non-rotation-aware clients.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per secret.' },
          steps: ['Identify secret type (DB credentials, API key, etc.).', 'For RDS-type: use AWS-managed rotation Lambda.', 'For custom: write rotation Lambda + IAM permissions.', 'Apply rotation_rules with automatically_after_days.'],
          example_code: `resource "aws_secretsmanager_secret" "db" {
  name        = "prod/rds/app"
  description = "RDS credential for prod app"
  rotation_rules { automatically_after_days = 30 }
}
resource "aws_secretsmanager_secret_rotation" "db" {
  secret_id           = aws_secretsmanager_secret.db.id
  rotation_lambda_arn = aws_lambda_function.rotation.arn
  rotation_rules { automatically_after_days = 30 }
}`,
          references: [{ title: 'Secrets Manager rotation', url: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ia-5','ia-5.1'],
    }),

    // L3: Rotation actually happens
    finding({
      rule: 'aws.secretsmanager.rotation_freshness',
      passed: secretsCollected && rotationStale.length === 0,
      severity: 'high',
      current: {
        summary: rotationStale.length === 0
          ? 'No secrets are past their rotation deadline.'
          : `${rotationStale.length} secret(s) are past their rotation deadline (LastRotatedDate older than RotationPeriod + ${STALE_ROTATION_BUFFER_DAYS}-day buffer).`,
        observations: { stale_rotations: rotationStale.map((s) => ({ Name: s.Name, period: s.RotationRulesAutomaticallyAfterDays, daysSince: s.DaysSinceLastRotation })) },
      },
      target: { summary: 'For every secret with rotation enabled, LastRotatedDate is within RotationPeriod + 7 days.', rationale: 'Configured rotation is meaningless if it isn\'t actually happening. NIST IA-5(1).' },
      gap: (secretsCollected && rotationStale.length === 0) ? undefined : {
        description: 'Rotation is scheduled but hasn\'t completed — Lambda failures, missing permissions, or upstream system unreachable.',
        affected_resources: rotationStale.map<AffectedResource>((s) => ({
          type: 'aws_secretsmanager_secret', identifier: s.ARN, name: s.Name,
          attributes: { rotation_period_days: s.RotationRulesAutomaticallyAfterDays, days_since_last_rotation: s.DaysSinceLastRotation, last_rotated: s.LastRotatedDate },
        })),
      },
      remediation: (secretsCollected && rotationStale.length === 0) ? undefined : {
        summary: 'Investigate rotation Lambda failures; manually trigger rotation if needed.',
        options: [{
          approach: 'Check rotation Lambda logs + retry.',
          mechanism: 'cli',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Manual rotation may cause downtime for non-rotation-aware clients.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per stale secret.' },
          steps: [
            'For each stale secret, inspect the rotation Lambda CloudWatch log group.',
            'Common failures: missing IAM permission on target DB, network connectivity from Lambda VPC, secret value format unexpected.',
            'Fix root cause.',
            'Run `aws secretsmanager rotate-secret --secret-id <ARN>` to force rotation.',
          ],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-5','ia-5.1'],
    }),

    // KMS CMK rotation
    finding({
      rule: 'aws.kms.cmk_rotation_enabled',
      passed: kmsCollected && customerKeysWithoutRotation.length === 0,
      severity: 'high',
      current: {
        summary: customerKeyCount === 0
          ? 'No customer-managed KMS keys (using AWS-managed keys only).'
          : (customerKeysWithoutRotation.length === 0
            ? `All ${customerKeyCount} customer-managed KMS key(s) have rotation enabled.`
            : `${customerKeysWithoutRotation.length} of ${customerKeyCount} customer-managed KMS key(s) lack rotation.`),
        observations: { customer_managed_keys: customerKeyCount, without_rotation: customerKeysWithoutRotation, total_keys: kmsKeys.length },
      },
      target: { summary: 'Every customer-managed CMK (symmetric, encryption-purpose) has automatic annual rotation enabled.', rationale: 'NIST SC-12. KMS rotation is one-line; absence indicates configuration oversight.' },
      gap: (kmsCollected && customerKeysWithoutRotation.length === 0) ? undefined : {
        description: 'Static CMK material increases blast radius if compromised.',
        affected_resources: customerKeysWithoutRotation.map<AffectedResource>((kid) => ({
          type: 'aws_kms_key', identifier: kid, name: kid, attributes: { rotation_enabled: false },
        })),
      },
      remediation: (kmsCollected && customerKeysWithoutRotation.length === 0) ? undefined : {
        summary: 'Enable rotation on each CMK via EnableKeyRotation API.',
        options: [{
          approach: 'Set enable_key_rotation=true via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'none', notes: 'Old key material remains valid for previously-encrypted data; new encryptions use new material.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Update aws_kms_key resources to set enable_key_rotation=true.', 'Apply Terraform.'],
          example_code: `resource "aws_kms_key" "app" {
  description         = "Application encryption"
  enable_key_rotation = true
  deletion_window_in_days = 30
}`,
          references: [{ title: 'KMS automatic key rotation', url: 'https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html' }],
        }],
      },
      alternative_satisfiers: [
        { via: 'CloudHSM or external HSM with manual rotation playbook', description: 'For BYOK / external-key-store configurations, rotation cadence is operator-driven.', evidence_required: ['HSM rotation runbook', 'Last rotation log'], detected: false },
      ],
      nist_controls: ['sc-12','sc-12.2'],
    }),

    // ACM certs expiring without renewal
    finding({
      rule: 'aws.acm.no_certs_expiring_without_renewal',
      passed: acmCollected && certsExpiringSoonNoRenewal.length === 0,
      severity: 'high',
      current: {
        summary: certsExpiringSoonNoRenewal.length === 0
          ? `${acmTotal} ACM cert(s); none expiring in <30 days without successful renewal.`
          : `${certsExpiringSoonNoRenewal.length} cert(s) expire in <30 days WITHOUT RenewalStatus=SUCCESS.`,
        observations: { total_certs: acmTotal, expiring_no_renewal: certsExpiringSoonNoRenewal.map((c2) => ({ domain: c2.DomainName, days: c2.DaysToExpiry, renewal: c2.RenewalStatus })) },
      },
      target: { summary: 'No cert expires in <30 days unless it has RenewalStatus=SUCCESS (auto-renewal succeeded).', rationale: 'NIST SC-12. Cert expiry = outage; failed auto-renewal = manual intervention needed.' },
      gap: (acmCollected && certsExpiringSoonNoRenewal.length === 0) ? undefined : {
        description: 'Cert outage imminent if no manual action.',
        affected_resources: certsExpiringSoonNoRenewal.map<AffectedResource>((c2) => ({
          type: 'aws_acm_certificate', identifier: c2.Arn, name: c2.DomainName,
          attributes: { NotAfter: c2.NotAfter, DaysToExpiry: c2.DaysToExpiry, RenewalStatus: c2.RenewalStatus },
        })),
      },
      remediation: (acmCollected && certsExpiringSoonNoRenewal.length === 0) ? undefined : {
        summary: 'Investigate per-cert renewal failure; check DNS validation records and CT log issues.',
        options: [{
          approach: 'Per-cert investigation.',
          mechanism: 'process',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'high', notes: 'Cert expiry causes TLS handshake failures.' },
          customer_visible: { level: 'high', notes: 'Service unavailable if cert expires.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per cert.' },
          steps: [
            'For each cert, check ACM console for renewal-failure reason.',
            'Common failures: missing DNS CNAME validation record (DNS-validated certs), domain ownership changed.',
            'Fix DNS records or re-issue cert.',
            'Verify RenewalStatus=SUCCESS.',
          ],
        }],
      },
      alternative_satisfiers: [
        { via: "Let's Encrypt + cert-manager / certbot", description: 'Off-ACM cert rotation via Let\'s Encrypt is fine if automated.', evidence_required: ['cert-manager Certificate CRD or certbot cron', 'Sample successful renewal log'], detected: false },
      ],
      nist_controls: ['sc-12'],
    }),

    // SSM SecureString CMK hygiene
    finding({
      rule: 'aws.ssm.securestring_uses_cmk',
      passed: ssmParamsCollected && (secureStringParamCount === 0 || (secureStringsWithDefaultKey / secureStringParamCount) < 0.5),
      severity: 'medium',
      current: {
        summary: secureStringParamCount === 0
          ? 'No SSM SecureString parameters.'
          : `${secureStringsWithDefaultKey} of ${secureStringParamCount} SecureString params use the AWS-managed default key (alias/aws/ssm).`,
        observations: { total: secureStringParamCount, with_default_key: secureStringsWithDefaultKey },
      },
      target: { summary: 'Most SecureString parameters use a customer-managed CMK (so key access can be policy-controlled).', rationale: 'NIST SC-13. AWS-managed default key has no key-policy control beyond IAM.' },
      gap: (ssmParamsCollected && (secureStringParamCount === 0 || (secureStringsWithDefaultKey / secureStringParamCount) < 0.5)) ? undefined : {
        description: 'Default-key SecureStrings cannot be access-controlled via key policy.',
        affected_resources: [{ type: 'aws_ssm_parameter', identifier: 'aggregate', attributes: { with_default_key: secureStringsWithDefaultKey } }],
      },
      remediation: (ssmParamsCollected && (secureStringParamCount === 0 || (secureStringsWithDefaultKey / secureStringParamCount) < 0.5)) ? undefined : {
        summary: 'Recreate SecureStrings with KeyId = customer CMK.',
        options: [{
          approach: 'Migrate parameters to CMK encryption.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'KMS usage charges.' },
          availability_impact: { level: 'low', notes: 'Coordinate with consumers; CMK access must be granted before re-encryption.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per parameter or fleet.' },
          steps: ['Create CMK with appropriate key policy.', 'Update aws_ssm_parameter resources to set key_id.', 'Verify consumers can decrypt.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-13'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
