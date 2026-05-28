/**
 * GCP inventory collector — KSI-PIY-GIV.
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

export async function collectPiyGiv(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Asset Inventory access check + feed presence
  let assetApiReachable = false;
  let assetCount = 0;
  let feedCount = 0;
  try {
    const ca = await gcpAuth.googleClient<any>('cloudasset', 'v1');
    try {
      // Quick search to verify API + count assets
      const r = await ca.assets.list({ parent: `projects/${ctx.project}`, pageSize: 100 });
      assetApiReachable = true;
      assetCount = (r.data.assets ?? []).length;
      evidence.push(ev('cloudasset.assets_sample', { count_sample: assetCount }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudasset.assets.list', 'cloudasset.assets.list (roles/cloudasset.viewer)')); }

    try {
      const r = await ca.feeds.list({ parent: `projects/${ctx.project}` });
      feedCount = r.data.feeds?.length ?? 0;
      evidence.push(ev('cloudasset.feeds_for_inventory', { count: feedCount }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudasset.feeds.list', 'cloudasset.feeds.list (roles/cloudasset.viewer)')); }
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudasset.googleClient', 'cloudasset.assets.list (roles/cloudasset.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External CSPM/CNAPP (Wiz, Lacework, Prisma)',
      description: '3rd-party tool maintains queryable asset inventory.',
      evidence_required: ['CSPM asset export', 'API/UI query sample'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.cloudasset.api_reachable',
      passed: assetApiReachable,
      severity: 'high',
      current: {
        summary: assetApiReachable
          ? `Cloud Asset Inventory queryable; ${feedCount} change-feed(s) configured.`
          : 'Cloud Asset Inventory API not reachable from this project — inventory may be manual.',
        observations: { asset_api_reachable: assetApiReachable, asset_sample_count: assetCount, feed_count: feedCount },
      },
      target: { summary: 'Cloud Asset Inventory queryable at project (ideally org) level, with feeds routing real-time change events.', rationale: 'NIST CM-8, PM-5.' },
      gap: assetApiReachable ? undefined : {
        description: 'No authoritative auto-inventory.',
        affected_resources: [{ type: 'google_cloud_asset_project_feed', identifier: 'none', attributes: {} }],
      },
      remediation: assetApiReachable ? undefined : {
        summary: 'Enable Cloud Asset Inventory API + create org/project-level feed.',
        options: [{
          approach: 'Enable + configure feed via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'API + Pub/Sub charges.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Enable + feed + downstream consumer.' },
          steps: ['Enable cloudasset.googleapis.com.', 'Create project / org feed routing to Pub/Sub.', 'Verify event flow.'],
          references: [{ title: 'Cloud Asset Inventory', url: 'https://cloud.google.com/asset-inventory/docs/overview' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cm-8','cm-8.1','pm-5'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'Asset feeds also drive drift detection.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
