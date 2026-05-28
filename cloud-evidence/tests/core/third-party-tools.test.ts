/**
 * Tests for core/detect/third-party-tools.ts — vendor/IaC/drift/GRC signatures.
 *
 * All inputs are synthetic, offline objects (IAM names, SAML/OIDC URLs, tags,
 * trusted external account IDs). We assert each vendor is detected from a
 * representative READ-ONLY signal and that satisfies_ksis is populated.
 */
import { describe, it, expect } from 'vitest';
import { detect } from '../../core/detect/third-party-tools.ts';
import type { AwsSignals, GcpSignals } from '../../core/detect/third-party-tools.ts';
import type { ThirdPartyToolMatch } from '../../core/envelope.ts';

type Signals = AwsSignals & GcpSignals;

/** Run detect() and return the match for a given canonical vendor name. */
function findTool(signals: Signals, vendor: string): ThirdPartyToolMatch | undefined {
  return detect(signals).find((t) => t.name === vendor);
}

describe('third-party-tool detector — IdP / SSO', () => {
  it.each([
    ['Okta', { iam_saml_provider_arns: ['arn:aws:iam::111122223333:saml-provider/Okta'] } as Signals],
    ['Okta', { iam_oidc_provider_urls: ['https://acme.okta.com'] } as Signals],
    ['Microsoft Entra ID (Azure AD)', { iam_oidc_provider_urls: ['https://sts.windows.net/abc/'] } as Signals],
    ['Microsoft Entra ID (Azure AD)', { iam_role_names: ['entra-sso-role'] } as Signals],
    ['Ping Identity', { iam_oidc_provider_urls: ['https://auth.pingone.com/abc/as'] } as Signals],
    ['Ping Identity', { iam_role_names: ['pingfederate-saml'] } as Signals],
    ['OneLogin', { iam_saml_provider_arns: ['arn:aws:iam::111122223333:saml-provider/OneLogin'] } as Signals],
    ['JumpCloud', { iam_role_names: ['jumpcloud-sso'] } as Signals],
  ])('detects %s and maps IAM KSIs', (vendor, signals) => {
    const tool = findTool(signals, vendor);
    expect(tool, `${vendor} should be detected`).toBeDefined();
    expect(tool!.satisfies_ksis.length).toBeGreaterThan(0);
    expect(tool!.satisfies_ksis.some((k) => k.startsWith('KSI-IAM'))).toBe(true);
    expect(tool!.detection_signals.length).toBeGreaterThan(0);
  });

  it('marks a SAML/OIDC federation signature as direct, a bare name as inferred', () => {
    expect(findTool({ iam_oidc_provider_urls: ['https://acme.okta.com'] }, 'Okta')!.confidence).toBe('direct');
    expect(findTool({ iam_role_names: ['okta-readonly'] }, 'Okta')!.confidence).toBe('inferred');
  });
});

describe('third-party-tool detector — vuln scanning / CNAPP', () => {
  it.each([
    ['Wiz', { iam_role_names: ['wiz-readonly-scanner'] } as Signals, 'VDR'],
    ['Prisma Cloud (Palo Alto)', { iam_role_names: ['prisma-cloud-role'] } as Signals, 'VDR'],
    ['Orca Security', { iam_role_names: ['orca-security-scanner'] } as Signals, 'VDR'],
    ['Tenable', { iam_role_names: ['tenable-io-connector'] } as Signals, 'VDR'],
    ['Qualys', { iam_role_names: ['qualys-cloud-connector'] } as Signals, 'VDR'],
    ['Snyk', { iam_role_names: ['snyk-iac-scan'] } as Signals, 'VDR'],
    ['Lacework', { service_account_emails: ['lacework@proj.iam.gserviceaccount.com'] } as Signals, 'VDR'],
    ['Aqua Security', { iam_role_names: ['aquasec-runtime'] } as Signals, 'VDR'],
  ])('detects %s with VDR-family credit', (vendor, signals, family) => {
    const tool = findTool(signals, vendor);
    expect(tool, `${vendor} should be detected`).toBeDefined();
    expect(tool!.satisfies_ksis).toContain(family);
    expect(tool!.satisfies_ksis.some((k) => k === 'KSI-SVC-VRI')).toBe(true);
  });

  it('treats Wiz trusted cross-account connector as a direct signature', () => {
    const tool = findTool({ trusted_external_account_ids: ['197171649850'] }, 'Wiz');
    expect(tool).toBeDefined();
    expect(tool!.confidence).toBe('direct');
  });
});

describe('third-party-tool detector — drift / IaC / GitOps', () => {
  it.each([
    ['Terraform Cloud / Enterprise', { iam_oidc_provider_urls: ['https://app.terraform.io'] } as Signals],
    ['Atlantis', { iam_role_names: ['atlantis-plan-apply'] } as Signals],
    ['env0', { iam_role_names: ['env0-deployer'] } as Signals],
    ['Spacelift', { iam_role_names: ['spacelift-stack-role'] } as Signals],
    ['Argo CD', { iam_role_names: ['argocd-application-controller'] } as Signals],
    ['Flux', { iam_role_names: ['flux-system-controller'] } as Signals],
  ])('detects %s and maps drift/CMT KSIs', (vendor, signals) => {
    const tool = findTool(signals, vendor);
    expect(tool, `${vendor} should be detected`).toBeDefined();
    expect(tool!.satisfies_ksis).toContain('KSI-CMT-RVP');
    expect(tool!.satisfies_ksis).toContain('KSI-CMT-RMV');
  });

  it('marks app.terraform.io OIDC federation as direct', () => {
    expect(findTool({ iam_oidc_provider_urls: ['https://app.terraform.io'] }, 'Terraform Cloud / Enterprise')!.confidence).toBe('direct');
  });
});

describe('third-party-tool detector — GRC / continuous compliance', () => {
  it.each([
    ['Vanta', { iam_role_names: ['vanta-auditor'] } as Signals],
    ['Drata', { iam_role_names: ['drata-autopilot'] } as Signals],
    ['Secureframe', { iam_role_names: ['secureframe-readonly'] } as Signals],
    ['Paramify', { iam_role_names: ['paramify-export'] } as Signals],
  ])('detects %s with CCM/PVA/AFR family credit', (vendor, signals) => {
    const tool = findTool(signals, vendor);
    expect(tool, `${vendor} should be detected`).toBeDefined();
    expect(tool!.satisfies_ksis).toContain('CCM');
    expect(tool!.satisfies_ksis).toContain('PVA');
    expect(tool!.satisfies_ksis).toContain('AFR');
  });
});

describe('third-party-tool detector — security training / LMS', () => {
  it.each([
    ['KnowBe4', { iam_role_names: ['knowbe4-scim'] } as Signals],
    ['Hoxhunt', { service_account_emails: ['hoxhunt@proj.iam.gserviceaccount.com'] } as Signals],
    ['Proofpoint Security Awareness', { iam_role_names: ['proofpoint-psat'] } as Signals],
  ])('detects %s with CED credit', (vendor, signals) => {
    const tool = findTool(signals, vendor);
    expect(tool, `${vendor} should be detected`).toBeDefined();
    expect(tool!.satisfies_ksis).toContain('CED');
  });
});

describe('third-party-tool detector — bug bounty / VDP', () => {
  it.each([
    ['HackerOne', { iam_role_names: ['hackerone-integration'] } as Signals],
    ['Bugcrowd', { iam_role_names: ['bugcrowd-connector'] } as Signals],
    ['Intigriti', { iam_role_names: ['intigriti-sync'] } as Signals],
  ])('detects %s with VDR credit', (vendor, signals) => {
    const tool = findTool(signals, vendor);
    expect(tool, `${vendor} should be detected`).toBeDefined();
    expect(tool!.satisfies_ksis).toContain('VDR');
  });
});

describe('third-party-tool detector — incident / on-call', () => {
  it.each([
    ['PagerDuty', { iam_role_names: ['pagerduty-events'] } as Signals],
    ['Opsgenie', { iam_role_names: ['opsgenie-integration'] } as Signals],
    ['ServiceNow SIR', { iam_role_names: ['servicenow-sir-integration'] } as Signals],
    ['Splunk SOAR', { iam_role_names: ['splunk-soar-action'] } as Signals],
  ])('detects %s with INR/ICP credit', (vendor, signals) => {
    const tool = findTool(signals, vendor);
    expect(tool, `${vendor} should be detected`).toBeDefined();
    expect(tool!.satisfies_ksis).toContain('INR');
    expect(tool!.satisfies_ksis).toContain('ICP');
  });

  it('detects ServiceNow SIR / PagerDuty via EventBridge target ARNs', () => {
    const pd = findTool({ eventbridge_rule_targets: [{ arn: 'arn:aws:events:us-east-1:1:api-destination/pagerduty' }] }, 'PagerDuty');
    expect(pd).toBeDefined();
  });
});

describe('third-party-tool detector — supply chain / signing', () => {
  it.each([
    ['Sigstore / cosign', { iam_oidc_provider_urls: ['https://oauth2.sigstore.dev/auth'] } as Signals, 'direct'],
    ['Sigstore / cosign', { iam_role_names: ['cosign-keyless-signer'] } as Signals, 'inferred'],
    ['Chainguard', { iam_role_names: ['chainguard-pull'] } as Signals, 'inferred'],
    ['Anchore', { iam_role_names: ['anchore-grype-scan'] } as Signals, 'inferred'],
  ])('detects %s with SCR/SVC-VRI credit (%s confidence)', (vendor, signals, conf) => {
    const tool = findTool(signals, vendor);
    expect(tool, `${vendor} should be detected`).toBeDefined();
    expect(tool!.confidence).toBe(conf);
    expect(tool!.satisfies_ksis).toContain('KSI-SCR-MON');
    expect(tool!.satisfies_ksis).toContain('KSI-SVC-VRI');
  });
});

describe('third-party-tool detector — read-only contract & regressions', () => {
  it('returns an empty array for empty signals (no false positives)', () => {
    expect(detect({})).toEqual([]);
  });

  it('still detects pre-existing tools (Teleport, Datadog, GitHub Actions OIDC)', () => {
    expect(findTool({ iam_role_names: ['teleport-access'] }, 'Teleport')).toBeDefined();
    expect(findTool({ iam_role_names: ['datadog-integration'] }, 'Datadog')).toBeDefined();
    expect(findTool({ iam_oidc_provider_urls: ['https://token.actions.githubusercontent.com'] }, 'GitHub Actions (OIDC federation)')).toBeDefined();
  });

  it('detects vendors from resource tags and labels (read-only metadata)', () => {
    const byTag = findTool({ resource_tags: [{ key: 'vendor', value: 'wiz' }] }, 'Wiz');
    expect(byTag).toBeDefined();
    const byLabel = findTool({ resource_labels: [{ key: 'managed-by', value: 'argocd' }] }, 'Argo CD');
    expect(byLabel).toBeDefined();
  });

  it('every emitted match carries a non-empty satisfies_ksis and detection_signals', () => {
    const all = detect({
      iam_role_names: ['okta-x', 'wiz-x', 'vanta-x', 'argocd-x', 'knowbe4-x', 'hackerone-x', 'opsgenie-x', 'cosign-x'],
    });
    expect(all.length).toBeGreaterThan(5);
    for (const t of all) {
      expect(t.satisfies_ksis.length).toBeGreaterThan(0);
      expect(t.detection_signals.length).toBeGreaterThan(0);
      expect(['direct', 'inferred']).toContain(t.confidence);
    }
  });
});
