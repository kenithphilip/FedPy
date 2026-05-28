/**
 * AWS inventory collector — KSI-PIY-GIV.
 * Tests: do you have an authoritative real-time inventory mechanism?
 */
import { DescribeConfigurationAggregatorsCommand, DescribeConfigurationRecordersCommand } from '@aws-sdk/client-config-service';
import { GetInventoryCommand } from '@aws-sdk/client-ssm';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

interface Ctx { region: string; auth: aws.AwsAuth; account: string | null; }
async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? 'us-east-1';
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) { try { account = (await aws.whoAmI(auth)).account; } catch { /* */ } }
  return { region, auth, account };
}

export async function collectPiyGiv(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Config aggregator — the multi-account inventory primitive
  let aggregatorCount = 0;
  let aggregatorNames: string[] = [];
  try {
    const cfg = aws.configService(ctx.auth);
    const r = await cfg.send(new DescribeConfigurationAggregatorsCommand({}));
    aggregatorCount = r.ConfigurationAggregators?.length ?? 0;
    aggregatorNames = (r.ConfigurationAggregators ?? []).map((a: any) => a.ConfigurationAggregatorName ?? '');
    evidence.push(ev('config.aggregators', { count: aggregatorCount, names: aggregatorNames }));
  } catch (e: any) { warnings.push(`Config aggregators: ${e.message}`); }

  // Config recorder presence (single-account)
  let recorderPresent = false;
  try {
    const cfg = aws.configService(ctx.auth);
    const r = await cfg.send(new DescribeConfigurationRecordersCommand({}));
    recorderPresent = (r.ConfigurationRecorders ?? []).length > 0;
    evidence.push(ev('config.recorder_for_inventory', { present: recorderPresent }));
  } catch (e: any) { warnings.push(`Config recorder: ${e.message}`); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External CSPM/CNAPP (Wiz, Lacework, Prisma Cloud) for authoritative inventory',
      description: '3rd-party tool maintains its own asset inventory queryable on demand.',
      evidence_required: ['CSPM asset inventory export', 'API/UI showing real-time asset query', 'Update freshness metric'],
      detected: false,
      detection_signals: [],
    },
    {
      via: 'SteampipeDB / Cloud Custodian / homegrown inventory script',
      description: 'Self-managed inventory tooling.',
      evidence_required: ['Tool config + schema', 'Sample real-time query result'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.config.aggregator_or_recorder_present',
      passed: aggregatorCount >= 1 || recorderPresent,
      severity: 'high',
      current: {
        summary: aggregatorCount >= 1
          ? `${aggregatorCount} Config aggregator(s) — org-wide inventory available.`
          : (recorderPresent ? 'Single-account Config recorder present (no org-wide aggregator).' : 'No Config aggregator AND no Config recorder.'),
        observations: { aggregator_count: aggregatorCount, aggregator_names: aggregatorNames, recorder_present: recorderPresent },
      },
      target: { summary: 'An AWS Config Aggregator collects from all in-scope accounts (multi-account org). For single-account scope, a Config recorder is sufficient.', rationale: 'NIST CM-8, PM-5. Authoritative inventory must be queryable real-time, not from a hand-maintained spreadsheet.' },
      gap: (aggregatorCount >= 1 || recorderPresent) ? undefined : {
        description: 'No automated inventory mechanism — inventory likely maintained manually.',
        affected_resources: [{ type: 'aws_config_configuration_aggregator', identifier: 'none', attributes: {} }],
      },
      remediation: (aggregatorCount >= 1 || recorderPresent) ? undefined : {
        summary: 'Create Config Aggregator covering all in-scope accounts.',
        options: [{
          approach: 'Org-wide Config Aggregator via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Config charges + aggregation; usually $hundreds/month.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Org integration + aggregator + verify.' },
          steps: ['Enable Config in each account.', 'Create Aggregator in security-tooling account with OrganizationAggregationSource.', 'Verify data flows from each account.'],
          example_code: `resource "aws_config_configuration_aggregator" "org" {
  name = "org"
  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.config_aggregator.arn
  }
}`,
          references: [{ title: 'Config Aggregator', url: 'https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cm-8','cm-8.1','pm-5'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-AFR-MAS', relationship: 'shares-remediation', note: 'PIY-GIV inventory feeds the MAS scope document.' },
        { ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'Same Config recorder.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
