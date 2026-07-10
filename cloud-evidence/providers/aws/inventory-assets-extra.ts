/**
 * Additional AWS asset depth-enrichers for identity + crypto services (INV-7b).
 *
 * The generic backbone (`discover.ts`) surfaces these as shallow rows if AWS
 * Config records them, but the security-relevant, per-resource facts a FedRAMP
 * inventory needs — access-key age, MFA presence, KMS key rotation — are NOT in
 * the Config/Resource-Explorer projection. This module fills them from the native
 * read-only APIs (clients already exist in core/auth/aws.ts):
 *
 *   - IAM users   → access-key age, MFA, console access (from the credential report)
 *   - IAM roles   → last-used, path (ListRoles)
 *   - KMS keys    → rotation enabled/period (GetKeyRotationStatus)
 *   - Secrets     → rotation config, last-changed (ListSecrets) — never the value
 *
 * These are account-global services, so like S3/CloudFront they are collected
 * once per run (gated by `includeGlobal`). Pure mappers are exported for tests.
 */
import {
  GenerateCredentialReportCommand,
  GetCredentialReportCommand,
  ListRolesCommand,
} from '@aws-sdk/client-iam';
import { ListKeysCommand, DescribeKeyCommand, GetKeyRotationStatusCommand } from '@aws-sdk/client-kms';
import { ListSecretsCommand } from '@aws-sdk/client-secrets-manager';
import * as aws from '../../core/auth/aws.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const MAX_PAGES = 200;

export interface AwsExtraResult { assets: CloudAsset[]; warnings: string[]; }

// --------------------------------------------------------------------------- #
// Credential-report parsing (pure) — the CSV the IAM console exposes.
// --------------------------------------------------------------------------- #

/** Parse the IAM credential-report CSV into row records keyed by column header. */
export function parseCredentialReport(csv: string): Record<string, string>[] {
  const lines = csv.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];
  const headers = lines[0]!.split(',');
  const rows: Record<string, string>[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = lines[i]!.split(',');
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => { row[h] = cells[idx] ?? ''; });
    rows.push(row);
  }
  return rows;
}

/** Whole-days between an ISO/epoch date string and now (null if unparseable/NA). */
function daysSince(value: string | undefined, nowMs: number): number | null {
  if (!value || value === 'N/A' || value === 'no_information' || value === 'not_supported') return null;
  const t = Date.parse(value);
  if (Number.isNaN(t)) return null;
  return Math.floor((nowMs - t) / 86_400_000);
}

/**
 * Map one credential-report row → a CloudAsset for the IAM user. `arn` comes
 * straight from the report; access-key age is the max of the two key rotation
 * dates; MFA + console-access are surfaced as governance signals.
 */
export function credentialRowToAsset(row: Record<string, string>, nowMs: number): CloudAsset | null {
  const arn = row.arn;
  const user = row.user;
  if (!arn || !user) return null;
  // The report has two key slots; take the oldest active one's age.
  const ages = [row.access_key_1_last_rotated, row.access_key_2_last_rotated]
    .map((d) => daysSince(d, nowMs))
    .filter((d): d is number => d != null);
  const keyAge = ages.length ? Math.max(...ages) : null;
  const mfa = row.mfa_active === 'true';
  const consoleEnabled = row.password_enabled === 'true';
  const isRoot = user === '<root_account>';
  const notes: string[] = [];
  if (consoleEnabled && !mfa) notes.push('console access WITHOUT MFA');
  if (keyAge != null && keyAge > 90) notes.push(`access key ${keyAge}d old (>90d)`);
  return {
    provider: 'aws',
    uniqueId: arn,
    resourceType: 'AWS::IAM::User',
    virtual: true,
    location: 'global',
    assetType: isRoot ? 'IAM Root Account' : 'IAM User',
    function: user,
    // Governance-bearing facts promoted to typed columns:
    accessKeyAgeDays: keyAge,
    mfaEnabled: mfa,
    lastUsedAt: (() => {
      const cands = [row.access_key_1_last_used_date, row.access_key_2_last_used_date, row.password_last_used]
        .filter((d) => d && d !== 'N/A' && d !== 'no_information');
      return cands.length ? cands.sort().at(-1) ?? null : null;
    })(),
    comments: notes.length ? notes.join('; ') : undefined,
  };
}

/** Map one KMS key + rotation status → CloudAsset. */
export function kmsKeyToAsset(
  arn: string | undefined,
  keyId: string | undefined,
  region: string,
  account: string | null,
  meta: { manager?: string; state?: string; created?: Date; rotation?: boolean; rotationDays?: number },
): CloudAsset | null {
  if (!arn && !keyId) return null;
  // Multi-region keys have a `mrk-` id prefix — DR-relevant, called out in FIPS.
  const multiRegion = (keyId ?? '').startsWith('mrk-') || (arn ?? '').includes(':key/mrk-');
  // AWS KMS in GovCloud is backed by FIPS 140-2 Level 3 validated HSMs for
  // AWS_KMS/AWS_CLOUDHSM origin keys; EXTERNAL/external-store keys need operator proof.
  const cmvp = meta.manager === 'AWS' || meta.manager === 'CUSTOMER'
    ? 'AWS KMS HSM — FIPS 140-2/140-3 CMVP validated (Level 3)'
    : null;
  return {
    provider: 'aws',
    uniqueId: arn ?? `arn:${aws.awsPartition(region)}:kms:${region}:${account ?? ''}:key/${keyId}`,
    resourceType: 'AWS::KMS::Key',
    virtual: true,
    location: region,
    assetType: 'Encryption Key',
    function: keyId ?? null,
    state: meta.state ?? null,
    createdAt: meta.created ? new Date(meta.created).toISOString() : null,
    encryptionAtRest: true,
    kmsRotationEnabled: meta.rotation ?? null,
    kmsRotationPeriodDays: meta.rotationDays ?? null,
    kmsMultiRegion: multiRegion,
    cmvpValidation: cmvp,
    // AWS-managed keys are noise for a CSP inventory; note the manager.
    comments: meta.manager ? `${meta.manager}-managed key${multiRegion ? '; multi-region' : ''}` : undefined,
  };
}

// --------------------------------------------------------------------------- #
// Collectors (account-global; gated by includeGlobal)
// --------------------------------------------------------------------------- #

/**
 * Enumerate IAM users (from the credential report), IAM roles, KMS keys (with
 * rotation), and Secrets Manager secrets (metadata only). Best-effort: each
 * source degrades to a warning without aborting the others.
 */
export async function collectAwsExtraAssets(
  auth: aws.AwsAuth,
  account: string | null,
  opts: { includeGlobal?: boolean; nowMs?: number } = {},
): Promise<AwsExtraResult> {
  const includeGlobal = opts.includeGlobal ?? true;
  const nowMs = opts.nowMs ?? Date.now();
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  const region = auth.region;

  // ---- IAM (global; once) ----
  if (includeGlobal) {
    try {
      const iam = aws.iam(auth);
      await iam.send(new GenerateCredentialReportCommand({}));
      const r = await iam.send(new GetCredentialReportCommand({}));
      const csv = Buffer.from(r.Content ?? new Uint8Array()).toString('utf8');
      for (const row of parseCredentialReport(csv)) {
        const a = credentialRowToAsset(row, nowMs);
        if (a) assets.push(a);
      }
    } catch (e: any) { warnings.push(`IAM credential report (iam:GetCredentialReport): ${e.message}`); }

    try {
      const iam = aws.iam(auth);
      let marker: string | undefined; let pages = 0;
      do {
        const r = await iam.send(new ListRolesCommand({ Marker: marker, MaxItems: 100 }));
        for (const role of r.Roles ?? []) {
          if (!role.Arn) continue;
          assets.push({
            provider: 'aws',
            uniqueId: role.Arn,
            resourceType: 'AWS::IAM::Role',
            virtual: true,
            location: 'global',
            assetType: 'IAM Role',
            function: role.RoleName ?? null,
            createdAt: role.CreateDate ? new Date(role.CreateDate).toISOString() : null,
            lastUsedAt: role.RoleLastUsed?.LastUsedDate ? new Date(role.RoleLastUsed.LastUsedDate).toISOString() : null,
          });
        }
        marker = r.Marker && r.Marker !== marker ? r.Marker : undefined;
      } while (marker && ++pages < MAX_PAGES);
    } catch (e: any) { warnings.push(`IAM roles (iam:ListRoles): ${e.message}`); }
  }

  // ---- KMS keys + rotation (regional) ----
  try {
    const kms = aws.kms(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await kms.send(new ListKeysCommand({ Marker: marker, Limit: 100 }));
      for (const k of r.Keys ?? []) {
        if (!k.KeyId) continue;
        let manager: string | undefined; let state: string | undefined; let created: Date | undefined;
        let rotation: boolean | undefined; let rotationDays: number | undefined;
        try {
          const d = await kms.send(new DescribeKeyCommand({ KeyId: k.KeyId }));
          manager = d.KeyMetadata?.KeyManager;
          state = d.KeyMetadata?.KeyState;
          created = d.KeyMetadata?.CreationDate;
        } catch { /* keep nulls */ }
        // Rotation status is only meaningful for customer-managed keys.
        if (manager !== 'AWS') {
          try {
            const rot = await kms.send(new GetKeyRotationStatusCommand({ KeyId: k.KeyId }));
            rotation = rot.KeyRotationEnabled;
            rotationDays = rot.RotationPeriodInDays;
          } catch { /* rotation status unavailable */ }
        }
        const a = kmsKeyToAsset(k.KeyArn, k.KeyId, region, account, { manager, state, created, rotation, rotationDays });
        if (a) assets.push(a);
      }
      marker = r.NextMarker && r.NextMarker !== marker ? r.NextMarker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`KMS keys (kms:ListKeys): ${e.message}`); }

  // ---- Secrets Manager (regional; metadata only — never the secret value) ----
  try {
    const sm = aws.secretsmanager(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await sm.send(new ListSecretsCommand({ NextToken: token, MaxResults: 100 }));
      for (const sec of r.SecretList ?? []) {
        if (!sec.ARN) continue;
        assets.push({
          provider: 'aws',
          uniqueId: sec.ARN,
          resourceType: 'AWS::SecretsManager::Secret',
          virtual: true,
          location: region,
          assetType: 'Secret',
          function: sec.Name ?? null,
          kmsKeyId: sec.KmsKeyId ?? null,
          encryptionAtRest: true, // Secrets Manager encrypts at rest with KMS always
          createdAt: sec.CreatedDate ? new Date(sec.CreatedDate).toISOString() : null,
          lastModifiedAt: sec.LastChangedDate ? new Date(sec.LastChangedDate).toISOString() : null,
          lastUsedAt: sec.LastAccessedDate ? new Date(sec.LastAccessedDate).toISOString() : null,
          tags: sec.Tags?.length ? Object.fromEntries(sec.Tags.filter((t) => t.Key).map((t) => [t.Key!, t.Value ?? ''])) : undefined,
          comments: sec.RotationEnabled ? 'rotation enabled' : 'rotation NOT enabled',
        });
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`Secrets Manager (secretsmanager:ListSecrets): ${e.message}`); }

  const now = new Date().toISOString();
  for (const a of assets) { a.accountId ??= account; a.collectedAt ??= now; a.sourceApi ??= 'aws-sdk-extra'; }
  return { assets, warnings };
}
