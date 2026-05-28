/**
 * Pattern-match against common 3rd-party tools used by SaaS CSPs.
 * Each detector takes provider-side inputs and returns ThirdPartyToolMatch[]
 * describing what was seen and which KSIs each tool helps satisfy.
 */
import type { ThirdPartyToolMatch } from '../envelope.ts';

export interface AwsSignals {
  iam_saml_provider_arns?: string[];
  iam_oidc_provider_urls?: string[];
  iam_user_names?: string[];
  iam_role_names?: string[];
  identity_center_present?: boolean;
  eventbridge_rule_targets?: Array<{ arn: string; ruleName?: string }>;
  secret_keys_in_secretsmanager?: string[];
}

export interface GcpSignals {
  workforce_pool_count?: number;
  workforce_pool_providers?: string[];
  iam_members?: string[];
  service_account_emails?: string[];
  eventarc_trigger_destinations?: string[];
  oidc_providers?: string[];
}

interface Rule {
  name: string;
  category: string;
  satisfies_ksis: string[];
  match: (s: AwsSignals & GcpSignals) => { hit: boolean; signals: string[]; confidence: 'direct' | 'inferred' } | null;
}

const RULES: Rule[] = [
  // ---- Identity / IdP ----
  {
    name: 'Okta',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-MFA', 'KSI-IAM-ELP'],
    match: (s) => {
      const hits: string[] = [];
      for (const a of s.iam_saml_provider_arns ?? []) if (/okta/i.test(a)) hits.push(`SAML provider: ${a}`);
      for (const u of s.iam_oidc_provider_urls ?? []) if (/okta\.com/i.test(u)) hits.push(`OIDC provider: ${u}`);
      for (const n of s.iam_role_names ?? []) if (/okta/i.test(n)) hits.push(`IAM role: ${n}`);
      for (const p of s.workforce_pool_providers ?? []) if (/okta/i.test(p)) hits.push(`Workforce pool provider: ${p}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Azure AD / Entra ID',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-MFA', 'KSI-IAM-ELP'],
    match: (s) => {
      const hits: string[] = [];
      for (const a of s.iam_saml_provider_arns ?? []) if (/azure|entra|microsoft/i.test(a)) hits.push(`SAML provider: ${a}`);
      for (const u of s.iam_oidc_provider_urls ?? []) if (/sts\.windows\.net|microsoftonline\.com|login\.microsoftonline/i.test(u)) hits.push(`OIDC provider: ${u}`);
      for (const p of s.workforce_pool_providers ?? []) if (/azure|entra|microsoft/i.test(p)) hits.push(`Workforce pool: ${p}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Google Workspace as IdP',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-MFA'],
    match: (s) => {
      const hits: string[] = [];
      for (const a of s.iam_saml_provider_arns ?? []) if (/google/i.test(a)) hits.push(`SAML provider: ${a}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },

  // ---- JIT / Bastion ----
  {
    name: 'Teleport',
    category: 'JIT / bastion',
    satisfies_ksis: ['KSI-IAM-JIT', 'KSI-IAM-ELP', 'KSI-IAM-MFA'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])]) {
        if (/teleport/i.test(n)) hits.push(`IAM principal: ${n}`);
      }
      for (const e of s.service_account_emails ?? []) if (/teleport/i.test(e)) hits.push(`GCP SA: ${e}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'ConductorOne',
    category: 'JIT / access governance',
    satisfies_ksis: ['KSI-IAM-JIT', 'KSI-IAM-ELP'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])]) {
        if (/conductorone|c1-/i.test(n)) hits.push(`IAM principal: ${n}`);
      }
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'StrongDM',
    category: 'JIT / bastion',
    satisfies_ksis: ['KSI-IAM-JIT'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])]) {
        if (/strongdm/i.test(n)) hits.push(`IAM principal: ${n}`);
      }
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },

  // ---- GRC / compliance automation ----
  {
    name: 'Vanta',
    category: 'GRC',
    satisfies_ksis: ['KSI-AFR-VDR', 'KSI-MLA-EVC', 'KSI-CNA-EIS'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])]) {
        if (/vanta/i.test(n)) hits.push(`IAM principal: ${n}`);
      }
      for (const e of s.service_account_emails ?? []) if (/vanta/i.test(e)) hits.push(`GCP SA: ${e}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Drata',
    category: 'GRC',
    satisfies_ksis: ['KSI-AFR-VDR', 'KSI-MLA-EVC'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])]) {
        if (/drata/i.test(n)) hits.push(`IAM principal: ${n}`);
      }
      for (const e of s.service_account_emails ?? []) if (/drata/i.test(e)) hits.push(`GCP SA: ${e}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Paramify',
    category: 'GRC (FedRAMP authoring)',
    satisfies_ksis: ['KSI-CSX-SUM', 'KSI-AFR-PVA'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])]) {
        if (/paramify/i.test(n)) hits.push(`IAM principal: ${n}`);
      }
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'SecureFrame',
    category: 'GRC',
    satisfies_ksis: ['KSI-AFR-VDR', 'KSI-MLA-EVC'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])]) {
        if (/secureframe/i.test(n)) hits.push(`IAM principal: ${n}`);
      }
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },

  // ---- SIEM / observability ----
  {
    name: 'Datadog',
    category: 'observability / SIEM',
    satisfies_ksis: ['KSI-MLA-OSM', 'KSI-MLA-LET', 'KSI-IAM-SUS'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/datadog/i.test(n)) hits.push(`IAM role: ${n}`);
      for (const e of s.service_account_emails ?? []) if (/datadog/i.test(e)) hits.push(`GCP SA: ${e}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Splunk',
    category: 'SIEM',
    satisfies_ksis: ['KSI-MLA-OSM', 'KSI-IAM-SUS'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/splunk/i.test(n)) hits.push(`IAM role: ${n}`);
      for (const e of s.service_account_emails ?? []) if (/splunk/i.test(e)) hits.push(`GCP SA: ${e}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Sumo Logic',
    category: 'SIEM',
    satisfies_ksis: ['KSI-MLA-OSM'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/sumo[\-_]?logic|sumologic/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Elastic / Elastic Security',
    category: 'SIEM',
    satisfies_ksis: ['KSI-MLA-OSM'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/elastic/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'New Relic',
    category: 'observability',
    satisfies_ksis: ['KSI-MLA-EVC'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/new[\-_]?relic/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },

  // ---- SOAR / Response Automation ----
  {
    name: 'Tines',
    category: 'SOAR',
    satisfies_ksis: ['KSI-IAM-SUS', 'KSI-INR-RIR'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/tines/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Torq',
    category: 'SOAR',
    satisfies_ksis: ['KSI-IAM-SUS', 'KSI-INR-RIR'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/torq/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'PagerDuty',
    category: 'on-call / IR',
    satisfies_ksis: ['KSI-INR-RIR', 'KSI-INR-AAR'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/pagerduty/i.test(n)) hits.push(`IAM role: ${n}`);
      for (const t of s.eventbridge_rule_targets ?? []) {
        if (/pagerduty/i.test(t.arn)) hits.push(`EventBridge target: ${t.arn}`);
      }
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },

  // ---- Threat detection / EDR ----
  {
    name: 'CrowdStrike',
    category: 'CWPP / EDR',
    satisfies_ksis: ['KSI-CNA-IBP', 'KSI-IAM-SUS', 'KSI-SVC-VRI'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/crowdstrike|falcon/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Wiz',
    category: 'CSPM',
    satisfies_ksis: ['KSI-CNA-IBP', 'KSI-CNA-EIS', 'KSI-MLA-EVC'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/^wiz/i.test(n) || /wiz-/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Lacework',
    category: 'CWPP / CSPM',
    satisfies_ksis: ['KSI-CNA-IBP', 'KSI-CNA-EIS'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/lacework/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'Snyk',
    category: 'SCA / supply chain',
    satisfies_ksis: ['KSI-SCR-MON', 'KSI-CMT-VTD'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of s.iam_role_names ?? []) if (/snyk/i.test(n)) hits.push(`IAM role: ${n}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },

  // ---- Secrets / cryptography ----
  {
    name: 'HashiCorp Vault',
    category: 'secrets management',
    satisfies_ksis: ['KSI-SVC-ASM', 'KSI-IAM-SNU'],
    match: (s) => {
      const hits: string[] = [];
      for (const n of [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])]) {
        if (/vault/i.test(n)) hits.push(`IAM principal: ${n}`);
      }
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },

  // ---- CI/CD ----
  {
    name: 'GitHub Actions (OIDC federation)',
    category: 'CI/CD',
    satisfies_ksis: ['KSI-IAM-SNU', 'KSI-CMT-VTD'],
    match: (s) => {
      const hits: string[] = [];
      for (const u of s.iam_oidc_provider_urls ?? []) if (/token\.actions\.githubusercontent\.com/i.test(u)) hits.push(`OIDC: ${u}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'GitLab CI (OIDC federation)',
    category: 'CI/CD',
    satisfies_ksis: ['KSI-IAM-SNU', 'KSI-CMT-VTD'],
    match: (s) => {
      const hits: string[] = [];
      for (const u of s.iam_oidc_provider_urls ?? []) if (/gitlab/i.test(u)) hits.push(`OIDC: ${u}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
  {
    name: 'CircleCI (OIDC federation)',
    category: 'CI/CD',
    satisfies_ksis: ['KSI-IAM-SNU', 'KSI-CMT-VTD'],
    match: (s) => {
      const hits: string[] = [];
      for (const u of s.iam_oidc_provider_urls ?? []) if (/circleci/i.test(u)) hits.push(`OIDC: ${u}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'direct' } : null;
    },
  },
];

export function detect(signals: AwsSignals & GcpSignals): ThirdPartyToolMatch[] {
  const out: ThirdPartyToolMatch[] = [];
  for (const r of RULES) {
    const m = r.match(signals);
    if (m?.hit) {
      out.push({
        name: r.name,
        category: r.category,
        confidence: m.confidence,
        detection_signals: m.signals,
        satisfies_ksis: r.satisfies_ksis,
      });
    }
  }
  return out;
}
