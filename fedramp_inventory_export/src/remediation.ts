/**
 * Security-lever remediation model.
 *
 * Maps each FAILING finding to the security tool / lever a security-engineering
 * team would deploy to close it — so the deliverable reads as a deployment plan
 * (enable GuardDuty, deploy Prisma/Inspector CNAPP, ship logs to SIEM, turn on
 * Config, enforce KMS, ...) rather than a flat list of control failures.
 *
 * Classification is by finding rule + NIST control, most-specific-first. Every
 * failing finding lands in exactly one lever (falling back to Governance/Process).
 * Pure + deterministic.
 */
import type { FlatFinding } from './join.ts';

export interface SecurityLever {
  /** Display name of the lever/tool. */
  name: string;
  /** Short category for grouping/ordering. */
  key: string;
  /** Which product/team typically owns deploying this. */
  defaultOwner: string;
}

/** The levers, in the order they should appear (deployment priority-ish). */
export const LEVERS: Record<string, SecurityLever> = {
  cnapp:       { key: 'cnapp',       name: 'CNAPP — Prisma Cloud / Inspector (vuln + posture)', defaultOwner: 'Product Security' },
  guardduty:   { key: 'guardduty',   name: 'Threat Detection — Amazon GuardDuty',              defaultOwner: 'Security Engineering' },
  securityhub: { key: 'securityhub', name: 'Posture Aggregation — AWS Security Hub',            defaultOwner: 'Security Engineering' },
  config:      { key: 'config',      name: 'Config & Drift — AWS Config',                       defaultOwner: 'Security Engineering' },
  cloudtrail:  { key: 'cloudtrail',  name: 'Audit Logging — AWS CloudTrail',                    defaultOwner: 'Security Engineering' },
  siem:        { key: 'siem',        name: 'Log Pipeline — CloudWatch / SIEM',                  defaultOwner: 'Security Engineering' },
  encryption:  { key: 'encryption',  name: 'Encryption & Keys — KMS / TLS / ACM',               defaultOwner: 'Platform / Security Eng' },
  secrets:     { key: 'secrets',     name: 'Secrets Management — Secrets Mgr / Vault',          defaultOwner: 'Platform Engineering' },
  iam:         { key: 'iam',         name: 'Identity & Access — IAM / Identity Center',         defaultOwner: 'Identity / Security Eng' },
  network:     { key: 'network',     name: 'Network & Edge — SG / WAF / Shield / VPC',          defaultOwner: 'Network / Security Eng' },
  backup:      { key: 'backup',      name: 'Resilience — Backup / DR / PITR',                   defaultOwner: 'Platform / SRE' },
  supplychain: { key: 'supplychain', name: 'Supply Chain — ECR scan / signing / SBOM',          defaultOwner: 'Product Security' },
  governance:  { key: 'governance',  name: 'Governance & Process (documented artifact)',        defaultOwner: 'GRC / Compliance' },
};

export const LEVER_ORDER = [
  'cnapp', 'guardduty', 'securityhub', 'config', 'cloudtrail', 'siem',
  'encryption', 'secrets', 'iam', 'network', 'backup', 'supplychain', 'governance',
];

/** Classify a finding to a lever key from its rule + controls. */
export function leverForFinding(f: FlatFinding): string {
  const rule = f.rule.toLowerCase();
  const ctrls = f.nistControls.map((c) => c.toLowerCase());
  const fam = (f.family ?? '').toUpperCase();
  const has = (...ids: string[]) => ids.some((id) => ctrls.some((c) => c === id || c.startsWith(id + '(')));

  // Most-specific rule signals first.
  if (/guardduty|threat.?detection|malware.?protection/.test(rule)) return 'guardduty';
  if (/security_?hub|securityhub/.test(rule)) return 'securityhub';
  if (/config\.|conformance|aws\.config|recorder|drift/.test(rule)) return 'config';
  if (/cloudtrail|trail|log_file_validation|insights_enabled|management_events|data_events/.test(rule)) return 'cloudtrail';
  if (/vdr|inspector|vulnerab|scan|cnapp|patch|kev|sla_breach/.test(rule)) return 'cnapp';
  if (/ecr|image_tag|scan_on_push|signer|signing|sbom|code_signing|supply.?chain/.test(rule)) return 'supplychain';
  if (/siem|log_export|log_retention|cloudwatch|logs?_|export_plumbing|alert_routing|osm|siem\b|central.*log/.test(rule)) return 'siem';
  if (/kms|encryption|tls|fips|cmvp|cert|acm|https|ssl/.test(rule)) return 'encryption';
  if (/secret|rotation|securestring|vault/.test(rule)) return 'secrets';
  if (/iam|mfa|access.?key|wildcard|admin|permission_set|password|cognito|identity_center|scp|access_analyzer|least.?priv|root/.test(rule)) return 'iam';
  if (/sg|security.?group|waf|shield|vpc|network|firewall|flow_log|public|egress|ingress|imdsv2|nacl|subnet|endpoint/.test(rule)) return 'network';
  if (/backup|pitr|restore|recovery|rpo|rto|snapshot|availability_zone|multi_?az|failover|abo|rpl/.test(rule)) return 'backup';

  // Fall back to control-family signals.
  if (has('ra-5', 'si-2', 'si-3')) return 'cnapp';
  if (has('si-4')) return 'guardduty';
  if (has('au-2', 'au-6', 'au-12')) return 'siem';
  if (has('sc-8', 'sc-12', 'sc-13', 'sc-28')) return 'encryption';
  if (has('ia-2', 'ia-5', 'ac-2', 'ac-6')) return 'iam';
  if (has('sc-7')) return 'network';
  if (has('cp-9', 'cp-10', 'cp-6')) return 'backup';
  if (has('cm-2', 'cm-6', 'cm-8', 'ca-7')) return 'config';

  // Process families are governance.
  if (['ADS', 'CCM', 'FSI', 'ICP', 'SCN', 'MAS', 'PVA', 'CED'].includes(fam)) return 'governance';
  return 'governance';
}
