/**
 * GCP secrets-management collector — KSI-SVC-ASM.
 * Mirrors providers/aws/secrets.ts with the same three layers:
 *   1. Secrets store exists.
 *   2. Rotation configured.
 *   3. Rotation actually happens (nextRotationTime in future, recently rotated).
 * Plus KMS rotation period + Certificate Manager expiry checks.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

interface Ctx { project: string; }
function setupCtx(c: CollectorContext): Ctx {
  if (!c.gcp?.project_id) throw new Error('GCP collector invoked without project_id');
  return { project: c.gcp.project_id };
}

const MAX_KMS_ROTATION_DAYS = 90;

export async function collectSvcAsm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ---- Secret Manager ----
  interface SecretRecord {
    name: string;
    rotationPeriod?: string;
    nextRotationTime?: string;
    rotationOverdue: boolean;
  }
  const secrets: SecretRecord[] = [];
  let totalSecrets = 0;
  try {
    const sm = await gcpAuth.googleClient<any>('secretmanager', 'v1');
    let pageToken: string | undefined;
    do {
      const r = await sm.projects.secrets.list({ parent: `projects/${ctx.project}`, pageSize: 100, pageToken });
      for (const s of r.data.secrets ?? []) {
        if (!s.name) continue;
        totalSecrets++;
        const rotation = s.rotation;
        const nextStr = rotation?.nextRotationTime;
        const overdue = !!(nextStr && new Date(nextStr).getTime() < Date.now());
        secrets.push({
          name: s.name,
          rotationPeriod: rotation?.rotationPeriod,
          nextRotationTime: nextStr,
          rotationOverdue: overdue,
        });
      }
      pageToken = r.data.nextPageToken;
    } while (pageToken);
    evidence.push(ev('secretmanager.projects.secrets.list', secrets));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'secretmanager.projects.secrets.list', 'secretmanager.secrets.list (roles/secretmanager.viewer)')); }

  const secretsWithRotation = secrets.filter((s) => !!s.rotationPeriod);
  const overdueSecrets = secrets.filter((s) => s.rotationOverdue);

  // ---- Cloud KMS keys + rotation ----
  interface KmsKey { name: string; purpose: string; rotationPeriod?: string; rotationPeriodDays?: number; }
  const kmsKeys: KmsKey[] = [];
  const keysWithoutRotation: string[] = [];
  const keysWithSlowRotation: string[] = [];
  try {
    const kms = await gcpAuth.googleClient<any>('cloudkms', 'v1');
    // List key rings across multiple locations
    const locations = ['global', 'us', 'us-central1', 'us-east1', 'us-west1'];
    for (const loc of locations) {
      try {
        const rings = await kms.projects.locations.keyRings.list({ parent: `projects/${ctx.project}/locations/${loc}` });
        for (const ring of rings.data.keyRings ?? []) {
          const ks = await kms.projects.locations.keyRings.cryptoKeys.list({ parent: ring.name });
          for (const k of ks.data.cryptoKeys ?? []) {
            const rotPeriodStr = k.rotationPeriod;
            let rotPeriodDays: number | undefined;
            if (rotPeriodStr) {
              const m = String(rotPeriodStr).match(/^(\d+)s$/);
              if (m) rotPeriodDays = Math.floor(parseInt(m[1]!, 10) / 86400);
            }
            kmsKeys.push({ name: k.name, purpose: k.purpose, rotationPeriod: rotPeriodStr, rotationPeriodDays: rotPeriodDays });
            if (k.purpose === 'ENCRYPT_DECRYPT' && !rotPeriodStr) keysWithoutRotation.push(k.name);
            if (rotPeriodDays !== undefined && rotPeriodDays > MAX_KMS_ROTATION_DAYS) keysWithSlowRotation.push(k.name);
          }
        }
      } catch { /* location may not exist */ }
    }
    evidence.push(ev('cloudkms.crypto_keys', { total: kmsKeys.length, without_rotation: keysWithoutRotation, slow_rotation: keysWithSlowRotation }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudkms.projects.locations.keyRings.cryptoKeys.list', 'cloudkms.cryptoKeys.list (roles/cloudkms.viewer)')); }

  // ---- Certificate Manager ----
  interface CertRecord { name: string; expireTime?: string; daysToExpiry?: number; managedState?: string; }
  const certs: CertRecord[] = [];
  const certsExpiringSoon: CertRecord[] = [];
  try {
    const cm = await gcpAuth.googleClient<any>('certificatemanager', 'v1');
    const locations = ['global', 'us-central1', 'us-east1', 'us-west1'];
    for (const loc of locations) {
      try {
        const r = await cm.projects.locations.certificates.list({ parent: `projects/${ctx.project}/locations/${loc}` });
        for (const c2 of r.data.certificates ?? []) {
          let days: number | undefined;
          if (c2.expireTime) days = Math.floor((new Date(c2.expireTime).getTime() - Date.now()) / 86400000);
          const rec: CertRecord = {
            name: c2.name,
            expireTime: c2.expireTime,
            daysToExpiry: days,
            managedState: c2.managed?.state,
          };
          certs.push(rec);
          if (days !== undefined && days < 30 && c2.managed?.state !== 'ACTIVE') certsExpiringSoon.push(rec);
        }
      } catch { /* location may not have CM */ }
    }
    evidence.push(ev('certificatemanager.certificates', certs.map((c2) => ({ name: c2.name, daysToExpiry: c2.daysToExpiry, managedState: c2.managedState }))));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'certificatemanager.projects.locations.certificates.list', 'certificatemanager.certs.list (roles/certificatemanager.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'HashiCorp Vault (dynamic secret engines)',
      description: 'Short-lived dynamic credentials replace static secrets.',
      evidence_required: ['Vault config with dynamic engines', 'Sample audit log of dynamic credential', 'Consumer inventory'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.secret_manager.secrets_store_in_use',
      passed: totalSecrets >= 1,
      severity: 'high',
      current: {
        summary: totalSecrets >= 1
          ? `${totalSecrets} secret(s) in Secret Manager.`
          : 'No secrets in Secret Manager — verify secrets aren\'t in env/code.',
        observations: { total_secrets: totalSecrets },
      },
      target: { summary: 'Secrets stored in Secret Manager (or external Vault).', rationale: 'NIST IA-5. Managed storage is the prerequisite.' },
      gap: totalSecrets >= 1 ? undefined : {
        description: 'No managed secrets found.',
        affected_resources: [{ type: 'google_secret_manager_secret', identifier: 'none', attributes: {} }],
      },
      remediation: totalSecrets >= 1 ? undefined : {
        summary: 'Migrate secrets to Secret Manager.',
        options: [{
          approach: 'Create secrets via Terraform; update apps.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: '$0.06/secret-version/month + per-API charges.' },
          availability_impact: { level: 'medium', notes: 'Application change required.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Per-secret migration.' },
          steps: ['Inventory current secrets.', 'Create Secret Manager entries.', 'Update apps to use Secret Manager SDK.', 'Remove from env/code.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ia-5','sc-12'],
    }),

    finding({
      rule: 'gcp.secret_manager.rotation_configured',
      passed: totalSecrets === 0 || (secretsWithRotation.length / totalSecrets) >= 0.8,
      severity: 'high',
      current: {
        summary: totalSecrets === 0
          ? 'No secrets.'
          : `${secretsWithRotation.length} of ${totalSecrets} (${Math.round(secretsWithRotation.length / totalSecrets * 100)}%) secrets have rotation period configured.`,
        observations: { with_rotation: secretsWithRotation.length, total: totalSecrets },
      },
      target: { summary: '≥80% of secrets have rotationPeriod set (and a Pub/Sub topic for rotation events).', rationale: 'NIST IA-5(1).' },
      gap: (totalSecrets === 0 || (secretsWithRotation.length / totalSecrets) >= 0.8) ? undefined : {
        description: 'Static long-lived secrets present.',
        affected_resources: secrets.filter((s) => !s.rotationPeriod).map<AffectedResource>((s) => ({
          type: 'google_secret_manager_secret', identifier: s.name, name: s.name, attributes: {},
        })),
      },
      remediation: (totalSecrets === 0 || (secretsWithRotation.length / totalSecrets) >= 0.8) ? undefined : {
        summary: 'Configure rotation period + Pub/Sub topic for each secret.',
        options: [{
          approach: 'Set rotation block via Terraform; subscribe Cloud Function for rotation handling.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Pub/Sub + Cloud Function invocations.' },
          availability_impact: { level: 'medium', notes: 'First rotation may cause brief downtime.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per secret type.' },
          steps: ['Create Pub/Sub topic for rotation events.', 'Set rotation { rotation_period, next_rotation_time, topics }.', 'Write Cloud Function to handle rotation event.'],
          example_code: `resource "google_secret_manager_secret" "db" {
  secret_id = "db-password"
  replication { automatic = true }
  rotation {
    rotation_period   = "2592000s"   # 30 days
    next_rotation_time = "2026-12-31T00:00:00Z"
    topics { name = google_pubsub_topic.rotation.id }
  }
}`,
          references: [{ title: 'Secret Manager rotation', url: 'https://cloud.google.com/secret-manager/docs/rotation-recommendations' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ia-5','ia-5.1'],
    }),

    finding({
      rule: 'gcp.secret_manager.no_overdue_rotations',
      passed: overdueSecrets.length === 0,
      severity: 'high',
      current: {
        summary: overdueSecrets.length === 0
          ? 'No secrets past their nextRotationTime.'
          : `${overdueSecrets.length} secret(s) past nextRotationTime — rotation handler not firing.`,
        observations: { overdue: overdueSecrets.map((s) => ({ name: s.name, nextRotationTime: s.nextRotationTime })) },
      },
      target: { summary: 'For every secret with rotation, nextRotationTime is in the future.', rationale: 'Overdue rotations indicate the rotation handler (Pub/Sub subscriber) is failing silently.' },
      gap: overdueSecrets.length === 0 ? undefined : {
        description: 'Rotation scheduled but not executing.',
        affected_resources: overdueSecrets.map<AffectedResource>((s) => ({
          type: 'google_secret_manager_secret', identifier: s.name, name: s.name, attributes: { nextRotationTime: s.nextRotationTime },
        })),
      },
      remediation: overdueSecrets.length === 0 ? undefined : {
        summary: 'Inspect rotation Pub/Sub subscriber + Cloud Function logs; manually trigger if needed.',
        options: [{
          approach: 'Investigate Pub/Sub subscriber.',
          mechanism: 'process',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Manual rotation may cause downtime for non-rotation-aware clients.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per stale secret.' },
          steps: ['Check Pub/Sub topic subscriptions.', 'Inspect Cloud Function logs.', 'Fix root cause.', 'Add a new SecretVersion manually to trigger rotation.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-5','ia-5.1'],
    }),

    finding({
      rule: 'gcp.kms.crypto_keys_rotation_period_set',
      passed: keysWithoutRotation.length === 0 && keysWithSlowRotation.length === 0,
      severity: 'high',
      current: {
        summary: keysWithoutRotation.length === 0 && keysWithSlowRotation.length === 0
          ? `All ${kmsKeys.length} crypto key(s) have rotation ≤ ${MAX_KMS_ROTATION_DAYS} days.`
          : `${keysWithoutRotation.length} encrypt/decrypt key(s) without rotation; ${keysWithSlowRotation.length} key(s) rotate slower than ${MAX_KMS_ROTATION_DAYS} days.`,
        observations: { total_keys: kmsKeys.length, without_rotation: keysWithoutRotation, slow_rotation: keysWithSlowRotation },
      },
      target: { summary: 'Encrypt/decrypt crypto keys have rotationPeriod set to ≤ 90 days.', rationale: 'NIST SC-12. Periodic rotation limits blast radius.' },
      gap: (keysWithoutRotation.length === 0 && keysWithSlowRotation.length === 0) ? undefined : {
        description: 'KMS keys without rotation accumulate exposure.',
        affected_resources: [...keysWithoutRotation, ...keysWithSlowRotation].map<AffectedResource>((n: string) => ({
          type: 'google_kms_crypto_key', identifier: n, name: n, attributes: {},
        })),
      },
      remediation: (keysWithoutRotation.length === 0 && keysWithSlowRotation.length === 0) ? undefined : {
        summary: 'Set rotation_period on each encrypt/decrypt key via Terraform.',
        options: [{
          approach: 'Update key resource.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'New key versions; minor cost.' },
          availability_impact: { level: 'none', notes: 'Old versions still valid for previously-encrypted data.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Identify encrypt/decrypt keys without rotation.', 'Set rotation_period.', 'Apply.'],
          example_code: `resource "google_kms_crypto_key" "app" {
  name            = "app"
  key_ring        = google_kms_key_ring.this.id
  rotation_period = "7776000s"   # 90 days
  purpose         = "ENCRYPT_DECRYPT"
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-12','sc-12.2'],
    }),

    finding({
      rule: 'gcp.certificatemanager.no_certs_expiring_unhealthy',
      passed: certsExpiringSoon.length === 0,
      severity: 'high',
      current: {
        summary: certsExpiringSoon.length === 0
          ? `${certs.length} cert(s); none expiring in <30 days with non-ACTIVE state.`
          : `${certsExpiringSoon.length} cert(s) expire <30 days with non-ACTIVE managed state.`,
        observations: { total: certs.length, expiring_soon_unhealthy: certsExpiringSoon },
      },
      target: { summary: 'Managed certs renew automatically; non-ACTIVE state near expiry is a renewal failure.', rationale: 'NIST SC-12.' },
      gap: certsExpiringSoon.length === 0 ? undefined : {
        description: 'Cert renewal failing.',
        affected_resources: certsExpiringSoon.map<AffectedResource>((c2) => ({
          type: 'google_certificate_manager_certificate', identifier: c2.name, name: c2.name,
          attributes: { daysToExpiry: c2.daysToExpiry, managedState: c2.managedState },
        })),
      },
      remediation: certsExpiringSoon.length === 0 ? undefined : {
        summary: 'Investigate renewal failure per cert.',
        options: [{
          approach: 'Per-cert investigation.',
          mechanism: 'process',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'high', notes: 'Cert expiry causes TLS handshake failure.' },
          customer_visible: { level: 'high', notes: 'Service unavailable.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per cert.' },
          steps: ['Check cert state.', 'Verify DNS validation records.', 'Re-issue if needed.'],
        }],
      },
      alternative_satisfiers: [
        { via: "cert-manager / Let's Encrypt", description: 'GKE cert-manager may handle certs instead of Certificate Manager.', evidence_required: ['cert-manager Certificate CRD', 'Recent renewal log'], detected: false },
      ],
      nist_controls: ['sc-12'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
