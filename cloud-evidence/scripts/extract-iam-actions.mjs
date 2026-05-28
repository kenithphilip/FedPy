#!/usr/bin/env node
/**
 * extract-iam-actions.mjs
 *
 * Auto-generate a machine-readable inventory of the cloud permissions the
 * collectors actually reference, by statically parsing the provider source:
 *
 *   - AWS: every `*Command` imported from `@aws-sdk/client-<svc>` maps to the
 *     IAM action `<iam-prefix>:<Action>` (e.g. `ListFunctionsCommand` from
 *     `@aws-sdk/client-lambda` → `lambda:ListFunctions`). Aliased imports
 *     (`X as Y`) resolve to the real command name `X`.
 *   - GCP: every `roles/...` string referenced in the file (the role hints we
 *     pass to `diagnoseGcpError`) is collected per file.
 *
 * Output: docs/iam-actions.generated.json — a deterministic, reviewable list
 * that complements the curated IAM-PERMISSIONS-CATALOG.md (run this to spot
 * drift between the docs and what the code calls).
 *
 * Usage:
 *   node scripts/extract-iam-actions.mjs            # write the JSON
 *   node scripts/extract-iam-actions.mjs --check    # exit 1 if it would change
 *
 * Pure helpers are exported for unit testing; the file only writes when run
 * directly.
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const PROVIDERS_DIR = resolve(REPO_ROOT, 'providers');
const OUT = resolve(REPO_ROOT, 'docs', 'iam-actions.generated.json');

/**
 * Map an `@aws-sdk/client-<slug>` package slug to its IAM service prefix.
 * Most slugs differ from the IAM prefix (e.g. cloudwatch-logs → logs), so the
 * non-trivial cases are listed explicitly. Unknown slugs fall back to the slug
 * with dashes stripped and are flagged `_unmapped` so the output stays honest.
 */
const SLUG_TO_IAM = {
  'accessanalyzer': 'access-analyzer',
  'acm': 'acm',
  'app-mesh': 'appmesh',
  'athena': 'athena',
  'auto-scaling': 'autoscaling',
  'backup': 'backup',
  'cloudformation': 'cloudformation',
  'cloudfront': 'cloudfront',
  'cloudtrail': 'cloudtrail',
  'cloudwatch-logs': 'logs',
  'codebuild': 'codebuild',
  'codepipeline': 'codepipeline',
  'cognito-identity-provider': 'cognito-idp',
  'config-service': 'config',
  'dynamodb': 'dynamodb',
  'ec2': 'ec2',
  'ecr': 'ecr',
  'eks': 'eks',
  'elastic-load-balancing-v2': 'elasticloadbalancing',
  'eventbridge': 'events',
  'firehose': 'firehose',
  'guardduty': 'guardduty',
  'iam': 'iam',
  'identitystore': 'identitystore',
  'inspector2': 'inspector2',
  'kms': 'kms',
  'lambda': 'lambda',
  'network-firewall': 'network-firewall',
  'organizations': 'organizations',
  'rds': 'rds',
  's3': 's3',
  'secrets-manager': 'secretsmanager',
  'securityhub': 'securityhub',
  'securitylake': 'securitylake',
  'shield': 'shield',
  'signer': 'signer',
  'sso-admin': 'sso',
  'ssm': 'ssm',
  'sts': 'sts',
  'wafv2': 'wafv2',
};

/** Resolve an AWS SDK package slug to its IAM prefix (best-effort). */
export function awsServiceToIamPrefix(slug) {
  return SLUG_TO_IAM[slug] ?? { prefix: slug.replace(/-/g, ''), _unmapped: true };
}

/**
 * Parse AWS `*Command` imports from one source file → array of `svc:Action`.
 * Handles multi-line import blocks and `X as Y` aliases.
 */
export function extractAwsActionsFromSource(src) {
  const actions = new Set();
  const unmappedSlugs = new Set();
  // Match `import { ... } from '@aws-sdk/client-<slug>'` (import block may span lines).
  const re = /import\s*(?:type\s*)?\{([\s\S]*?)\}\s*from\s*['"]@aws-sdk\/client-([a-z0-9-]+)['"]/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const names = m[1];
    const slug = m[2];
    const mapped = awsServiceToIamPrefix(slug);
    const prefix = typeof mapped === 'string' ? mapped : mapped.prefix;
    if (typeof mapped !== 'string') unmappedSlugs.add(slug);
    for (const raw of names.split(',')) {
      // `GetFindingsCommand as ShGetFindingsCommand` → real name is the part before ` as `.
      const name = raw.trim().split(/\s+as\s+/)[0]?.trim();
      if (!name || !name.endsWith('Command')) continue;
      const action = name.slice(0, -'Command'.length);
      if (!action) continue;
      actions.add(`${prefix}:${action}`);
    }
  }
  return { actions: [...actions].sort(), unmappedSlugs: [...unmappedSlugs].sort() };
}

/** Collect every `roles/...` reference in a GCP source file. */
export function extractGcpRolesFromSource(src) {
  const roles = new Set();
  // Role id must end on an alphanumeric so a trailing sentence period
  // ("…roles/iam.workloadIdentityUser.") isn't captured as part of the id.
  const re = /roles\/[A-Za-z][A-Za-z0-9._]*[A-Za-z0-9]/g;
  let m;
  while ((m = re.exec(src)) !== null) roles.add(m[0]);
  return [...roles].sort();
}

function listTsFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith('.ts') && !f.endsWith('.d.ts')).sort();
}

/** Build the full inventory object from disk. */
export function buildInventory() {
  const aws = { actions: new Set(), by_file: {}, services: new Set(), unmapped_slugs: new Set() };
  for (const f of listTsFiles(join(PROVIDERS_DIR, 'aws'))) {
    const src = readFileSync(join(PROVIDERS_DIR, 'aws', f), 'utf8');
    const { actions, unmappedSlugs } = extractAwsActionsFromSource(src);
    if (actions.length) aws.by_file[`aws/${f}`] = actions;
    for (const a of actions) { aws.actions.add(a); aws.services.add(a.split(':')[0]); }
    for (const s of unmappedSlugs) aws.unmapped_slugs.add(s);
  }
  const gcp = { roles: new Set(), by_file: {} };
  for (const f of listTsFiles(join(PROVIDERS_DIR, 'gcp'))) {
    const src = readFileSync(join(PROVIDERS_DIR, 'gcp', f), 'utf8');
    const roles = extractGcpRolesFromSource(src);
    if (roles.length) gcp.by_file[`gcp/${f}`] = roles;
    for (const r of roles) gcp.roles.add(r);
  }
  return {
    _source: 'auto-generated from providers/**/*.ts by scripts/extract-iam-actions.mjs',
    _generated_at: new Date().toISOString(),
    _note: 'Static analysis of *Command imports (AWS) and roles/* hints (GCP). Complements the curated IAM-PERMISSIONS-CATALOG.md; both are read-only.',
    aws: {
      action_count: aws.actions.size,
      service_count: aws.services.size,
      services: [...aws.services].sort(),
      actions: [...aws.actions].sort(),
      unmapped_slugs: [...aws.unmapped_slugs].sort(),
      by_file: aws.by_file,
    },
    gcp: {
      role_count: gcp.roles.size,
      roles: [...gcp.roles].sort(),
      by_file: gcp.by_file,
    },
  };
}

// ---- main (only when run directly) ----
// Compare decoded paths so a repo path containing spaces (file://…%20…) still matches.
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const inv = buildInventory();
  const json = JSON.stringify(inv, null, 2);
  if (process.argv.includes('--check')) {
    const existing = existsSync(OUT) ? readFileSync(OUT, 'utf8') : '';
    // Compare ignoring the volatile _generated_at line.
    const strip = (s) => s.replace(/"_generated_at":\s*"[^"]*",?\n/, '');
    if (strip(existing) !== strip(json)) {
      console.error('[extract-iam-actions] docs/iam-actions.generated.json is stale — run `node scripts/extract-iam-actions.mjs`.');
      process.exit(1);
    }
    console.error('[extract-iam-actions] up to date.');
  } else {
    writeFileSync(OUT, json);
    console.error(`[extract-iam-actions] AWS: ${inv.aws.action_count} actions across ${inv.aws.service_count} services; GCP: ${inv.gcp.role_count} roles. Wrote ${OUT}`);
    if (inv.aws.unmapped_slugs.length) console.error(`[extract-iam-actions] note: unmapped AWS slugs (verify IAM prefix): ${inv.aws.unmapped_slugs.join(', ')}`);
  }
}
