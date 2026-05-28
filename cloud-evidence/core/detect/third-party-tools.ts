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
  /** Managed/inline IAM policy names (often carry a vendor marker, e.g. "wiz-readonly"). */
  iam_policy_names?: string[];
  identity_center_present?: boolean;
  eventbridge_rule_targets?: Array<{ arn: string; ruleName?: string }>;
  secret_keys_in_secretsmanager?: string[];
  /** External AWS account IDs trusted by cross-account roles (e.g. a vendor's SaaS account). */
  trusted_external_account_ids?: string[];
  /** Resource tag values/keys seen across the account (e.g. {"vendor":"wiz"}). */
  resource_tags?: Array<{ key: string; value: string }>;
}

export interface GcpSignals {
  workforce_pool_count?: number;
  workforce_pool_providers?: string[];
  iam_members?: string[];
  service_account_emails?: string[];
  eventarc_trigger_destinations?: string[];
  oidc_providers?: string[];
  /** GCP workload-identity-pool provider issuer URIs (e.g. an external SaaS OIDC issuer). */
  workload_identity_pool_issuers?: string[];
  /** GCP resource label key/value pairs seen across the project. */
  resource_labels?: Array<{ key: string; value: string }>;
}

interface Rule {
  name: string;
  category: string;
  satisfies_ksis: string[];
  match: (s: AwsSignals & GcpSignals) => { hit: boolean; signals: string[]; confidence: 'direct' | 'inferred' } | null;
}

// ── Shared, read-only signal scanners ───────────────────────────────────────
/** All IAM principal names (roles + users), used for heuristic name matches. */
function principalNames(s: AwsSignals & GcpSignals): string[] {
  return [...(s.iam_role_names ?? []), ...(s.iam_user_names ?? [])];
}

/**
 * Scan the common name-bearing signals (IAM roles/users/policies, GCP SAs/members,
 * resource tags/labels) for a vendor marker. Returns labeled hit strings.
 * Pure: only inspects already-gathered READ-ONLY data.
 */
function scanNames(s: AwsSignals & GcpSignals, re: RegExp): string[] {
  const hits: string[] = [];
  for (const n of s.iam_role_names ?? []) if (re.test(n)) hits.push(`IAM role: ${n}`);
  for (const n of s.iam_user_names ?? []) if (re.test(n)) hits.push(`IAM user: ${n}`);
  for (const n of s.iam_policy_names ?? []) if (re.test(n)) hits.push(`IAM policy: ${n}`);
  for (const e of s.service_account_emails ?? []) if (re.test(e)) hits.push(`GCP SA: ${e}`);
  for (const m of s.iam_members ?? []) if (re.test(m)) hits.push(`GCP IAM member: ${m}`);
  for (const t of s.resource_tags ?? []) if (re.test(t.key) || re.test(t.value)) hits.push(`tag: ${t.key}=${t.value}`);
  for (const l of s.resource_labels ?? []) if (re.test(l.key) || re.test(l.value)) hits.push(`label: ${l.key}=${l.value}`);
  return hits;
}

/** Scan SAML provider ARNs + OIDC/issuer URLs + workforce/workload pools for a marker. */
function scanFederation(s: AwsSignals & GcpSignals, re: RegExp): string[] {
  const hits: string[] = [];
  for (const a of s.iam_saml_provider_arns ?? []) if (re.test(a)) hits.push(`SAML provider: ${a}`);
  for (const u of s.iam_oidc_provider_urls ?? []) if (re.test(u)) hits.push(`OIDC provider: ${u}`);
  for (const p of s.workforce_pool_providers ?? []) if (re.test(p)) hits.push(`Workforce pool provider: ${p}`);
  for (const i of s.workload_identity_pool_issuers ?? []) if (re.test(i)) hits.push(`Workload-identity issuer: ${i}`);
  for (const o of s.oidc_providers ?? []) if (re.test(o)) hits.push(`OIDC provider: ${o}`);
  return hits;
}

/** Scan trusted cross-account external account IDs against a set of known vendor SaaS account IDs. */
function scanTrustedAccounts(s: AwsSignals & GcpSignals, knownIds: string[]): string[] {
  const hits: string[] = [];
  for (const id of s.trusted_external_account_ids ?? []) {
    if (knownIds.includes(id)) hits.push(`Trusted external account: ${id}`);
  }
  return hits;
}

const RULES: Rule[] = [
  // ---- Identity / IdP ----
  {
    name: 'Okta',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-MFA', 'KSI-IAM-ELP', 'KSI-IAM-SNU'],
    match: (s) => {
      // A SAML/OIDC federation pointing at okta.com is an unambiguous (direct) signature.
      const fed = scanFederation(s, /okta(?:preview)?\.com|okta/i);
      const names = scanNames(s, /okta/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'Microsoft Entra ID (Azure AD)',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-MFA', 'KSI-IAM-ELP', 'KSI-IAM-SNU'],
    match: (s) => {
      const fed = scanFederation(s, /sts\.windows\.net|microsoftonline\.com|login\.microsoftonline|azure|entra|microsoft/i);
      const names = scanNames(s, /entra|azure[\-_]?ad|aad/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'Ping Identity',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-MFA', 'KSI-IAM-SNU'],
    match: (s) => {
      const fed = scanFederation(s, /pingone\.com|pingidentity\.com|pingfederate|pingone|pingfed/i);
      const names = scanNames(s, /ping[\-_]?(?:one|identity|federate)|pingfed/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'OneLogin',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-MFA', 'KSI-IAM-SNU'],
    match: (s) => {
      const fed = scanFederation(s, /onelogin/i);
      const names = scanNames(s, /onelogin/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'JumpCloud',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-MFA', 'KSI-IAM-SNU'],
    match: (s) => {
      const fed = scanFederation(s, /jumpcloud/i);
      const names = scanNames(s, /jumpcloud/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'Google Workspace as IdP',
    category: 'IdP',
    satisfies_ksis: ['KSI-IAM-AAM', 'KSI-IAM-MFA'],
    match: (s) => {
      const hits: string[] = [];
      for (const a of s.iam_saml_provider_arns ?? []) if (/google/i.test(a)) hits.push(`SAML provider: ${a}`);
      for (const u of s.iam_oidc_provider_urls ?? []) if (/accounts\.google\.com/i.test(u)) hits.push(`OIDC provider: ${u}`);
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
    category: 'GRC / continuous compliance',
    satisfies_ksis: ['CCM', 'PVA', 'AFR', 'MAS', 'KSI-AFR-VDR', 'KSI-MLA-EVC', 'KSI-CNA-EIS'],
    match: (s) => {
      const hits = scanNames(s, /vanta/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Drata',
    category: 'GRC / continuous compliance',
    satisfies_ksis: ['CCM', 'PVA', 'AFR', 'MAS', 'KSI-AFR-VDR', 'KSI-MLA-EVC'],
    match: (s) => {
      const hits = scanNames(s, /drata/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Secureframe',
    category: 'GRC / continuous compliance',
    satisfies_ksis: ['CCM', 'PVA', 'AFR', 'MAS', 'KSI-AFR-VDR', 'KSI-MLA-EVC'],
    match: (s) => {
      const hits = scanNames(s, /secureframe/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Paramify',
    category: 'GRC (FedRAMP authoring)',
    satisfies_ksis: ['CCM', 'PVA', 'AFR', 'MAS', 'KSI-CSX-SUM', 'KSI-AFR-PVA'],
    match: (s) => {
      const hits = scanNames(s, /paramify/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },

  // ---- Drift detection / IaC / GitOps ----
  {
    name: 'Terraform Cloud / Enterprise',
    category: 'IaC / drift detection',
    satisfies_ksis: ['KSI-CMT-RVP', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-CNA-EIS'],
    match: (s) => {
      // OIDC federation from app.terraform.io / TFC dynamic credentials is a direct signature.
      const fed = scanFederation(s, /app\.terraform\.io|terraform\.io/i);
      const names = scanNames(s, /terraform[\-_]?(?:cloud|enterprise|run|apply)|\btfc\b|\btfe\b/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'Atlantis',
    category: 'IaC / drift detection',
    satisfies_ksis: ['KSI-CMT-RVP', 'KSI-CMT-RMV', 'KSI-MLA-EVC'],
    match: (s) => {
      const hits = scanNames(s, /atlantis/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'env0',
    category: 'IaC / drift detection',
    satisfies_ksis: ['KSI-CMT-RVP', 'KSI-CMT-RMV', 'KSI-MLA-EVC'],
    match: (s) => {
      const fed = scanFederation(s, /env0\.com/i);
      const names = scanNames(s, /\benv0\b|env0[\-_]/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'Spacelift',
    category: 'IaC / drift detection',
    satisfies_ksis: ['KSI-CMT-RVP', 'KSI-CMT-RMV', 'KSI-MLA-EVC'],
    match: (s) => {
      const fed = scanFederation(s, /spacelift\.io/i);
      const names = scanNames(s, /spacelift/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'Argo CD',
    category: 'GitOps / drift detection',
    satisfies_ksis: ['KSI-CMT-RVP', 'KSI-CMT-RMV', 'KSI-CNA-EIS', 'KSI-MLA-EVC'],
    match: (s) => {
      const hits = scanNames(s, /argo[\-_]?cd|argocd/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Flux',
    category: 'GitOps / drift detection',
    satisfies_ksis: ['KSI-CMT-RVP', 'KSI-CMT-RMV', 'KSI-CNA-EIS'],
    match: (s) => {
      const hits = scanNames(s, /\bfluxcd\b|flux[\-_]?(?:system|cd)/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },

  // ---- Security training / LMS ----
  {
    name: 'KnowBe4',
    category: 'security awareness / LMS',
    satisfies_ksis: ['CED', 'KSI-CED-DET'],
    match: (s) => {
      const hits = scanNames(s, /knowbe4|know[\-_]?be4/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Hoxhunt',
    category: 'security awareness / LMS',
    satisfies_ksis: ['CED', 'KSI-CED-DET'],
    match: (s) => {
      const hits = scanNames(s, /hoxhunt/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Proofpoint Security Awareness',
    category: 'security awareness / LMS',
    satisfies_ksis: ['CED', 'KSI-CED-DET'],
    match: (s) => {
      const hits = scanNames(s, /proofpoint|wombat[\-_]?security/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },

  // ---- Bug bounty / vulnerability disclosure ----
  {
    name: 'HackerOne',
    category: 'bug bounty / VDP',
    satisfies_ksis: ['VDR', 'VDR-BST-SIR'],
    match: (s) => {
      const hits = scanNames(s, /hackerone|\bh1[\-_]/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Bugcrowd',
    category: 'bug bounty / VDP',
    satisfies_ksis: ['VDR', 'VDR-BST-SIR'],
    match: (s) => {
      const hits = scanNames(s, /bugcrowd/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Intigriti',
    category: 'bug bounty / VDP',
    satisfies_ksis: ['VDR', 'VDR-BST-SIR'],
    match: (s) => {
      const hits = scanNames(s, /intigriti/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },

  // ---- Incident / on-call ----
  {
    name: 'Opsgenie',
    category: 'on-call / IR',
    satisfies_ksis: ['INR', 'ICP', 'FSI', 'KSI-IAM-SUS', 'KSI-INR-RIR'],
    match: (s) => {
      const hits: string[] = [...scanNames(s, /opsgenie/i)];
      for (const t of s.eventbridge_rule_targets ?? []) if (/opsgenie/i.test(t.arn)) hits.push(`EventBridge target: ${t.arn}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'ServiceNow SIR',
    category: 'on-call / ITSM / IR',
    satisfies_ksis: ['INR', 'ICP', 'FSI', 'KSI-INR-RIR'],
    match: (s) => {
      const hits: string[] = [...scanNames(s, /servicenow|\bsnow[\-_]|[\-_]sir\b|service[\-_]?now/i)];
      for (const t of s.eventbridge_rule_targets ?? []) if (/servicenow/i.test(t.arn)) hits.push(`EventBridge target: ${t.arn}`);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Splunk SOAR',
    category: 'SOAR / IR',
    satisfies_ksis: ['INR', 'ICP', 'KSI-IAM-SUS', 'KSI-INR-RIR'],
    match: (s) => {
      const hits = scanNames(s, /splunk[\-_]?soar|phantom[\-_]?soar|\bphantom\b/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },

  // ---- Supply chain / artifact signing ----
  {
    name: 'Sigstore / cosign',
    category: 'supply chain / signing',
    satisfies_ksis: ['KSI-SCR-MON', 'KSI-SVC-VRI', 'KSI-CMT-VTD'],
    match: (s) => {
      // Keyless cosign uses Fulcio/Rekor OIDC federation — a direct signature.
      const fed = scanFederation(s, /fulcio\.sigstore\.dev|oauth2\.sigstore\.dev|rekor\.sigstore\.dev|sigstore/i);
      const names = scanNames(s, /sigstore|cosign|fulcio|rekor/i);
      const hits = [...fed, ...names];
      return hits.length ? { hit: true, signals: hits, confidence: fed.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'Chainguard',
    category: 'supply chain / signing',
    satisfies_ksis: ['KSI-SCR-MON', 'KSI-SVC-VRI', 'KSI-CMT-VTD'],
    match: (s) => {
      const hits = scanNames(s, /chainguard/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Anchore',
    category: 'supply chain / SBOM scanning',
    satisfies_ksis: ['KSI-SCR-MON', 'KSI-SVC-VRI', 'KSI-CMT-VTD'],
    match: (s) => {
      const hits = scanNames(s, /anchore|\bgrype\b|\bsyft\b/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
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
    satisfies_ksis: ['INR', 'ICP', 'FSI', 'KSI-INR-RIR', 'KSI-INR-AAR'],
    match: (s) => {
      const hits: string[] = [...scanNames(s, /pagerduty/i)];
      for (const t of s.eventbridge_rule_targets ?? []) {
        if (/pagerduty/i.test(t.arn)) hits.push(`EventBridge target: ${t.arn}`);
      }
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
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
    category: 'CNAPP / vuln scanning',
    satisfies_ksis: ['VDR', 'KSI-SVC-VRI', 'KSI-CNA-IBP', 'KSI-CNA-EIS', 'KSI-MLA-EVC', 'KSI-SCR-MON', 'KSI-CMT-RVP', 'KSI-CMT-RMV'],
    match: (s) => {
      const names = scanNames(s, /\bwiz\b|wiz[\-_]|^wiz/i);
      // Wiz's SaaS connector account ID is a direct signature when trusted cross-account.
      const accts = scanTrustedAccounts(s, ['197171649850']);
      const hits = [...names, ...accts];
      return hits.length ? { hit: true, signals: hits, confidence: accts.length ? 'direct' : 'inferred' } : null;
    },
  },
  {
    name: 'Prisma Cloud (Palo Alto)',
    category: 'CNAPP / vuln scanning',
    satisfies_ksis: ['VDR', 'KSI-SVC-VRI', 'KSI-CNA-IBP', 'KSI-CNA-EIS', 'KSI-MLA-EVC', 'KSI-SCR-MON'],
    match: (s) => {
      const hits = scanNames(s, /prisma[\-_]?cloud|prismacloud|redlock|twistlock/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Orca Security',
    category: 'CNAPP / vuln scanning',
    satisfies_ksis: ['VDR', 'KSI-SVC-VRI', 'KSI-CNA-IBP', 'KSI-CNA-EIS', 'KSI-SCR-MON'],
    match: (s) => {
      const hits = scanNames(s, /\borca\b|orca[\-_]?security/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Tenable',
    category: 'vuln scanning',
    satisfies_ksis: ['VDR', 'KSI-SVC-VRI', 'KSI-SCR-MON', 'KSI-CNA-EIS'],
    match: (s) => {
      const hits = scanNames(s, /tenable|nessus/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Qualys',
    category: 'vuln scanning',
    satisfies_ksis: ['VDR', 'KSI-SVC-VRI', 'KSI-SCR-MON', 'KSI-CNA-EIS'],
    match: (s) => {
      const hits = scanNames(s, /qualys/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Lacework',
    category: 'CNAPP / vuln scanning',
    satisfies_ksis: ['VDR', 'KSI-SVC-VRI', 'KSI-CNA-IBP', 'KSI-CNA-EIS', 'KSI-SCR-MON'],
    match: (s) => {
      const hits = scanNames(s, /lacework/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Aqua Security',
    category: 'CNAPP / container security',
    satisfies_ksis: ['VDR', 'KSI-SVC-VRI', 'KSI-CNA-IBP', 'KSI-SCR-MON', 'KSI-CMT-VTD'],
    match: (s) => {
      const hits = scanNames(s, /aqua[\-_]?(?:sec|security)|aquasec|\btrivy\b/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
    },
  },
  {
    name: 'Snyk',
    category: 'SCA / supply chain / vuln scanning',
    satisfies_ksis: ['VDR', 'KSI-SCR-MON', 'KSI-SVC-VRI', 'KSI-CMT-VTD'],
    match: (s) => {
      const hits = scanNames(s, /snyk/i);
      return hits.length ? { hit: true, signals: hits, confidence: 'inferred' } : null;
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
