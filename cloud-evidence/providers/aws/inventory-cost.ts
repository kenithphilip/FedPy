/**
 * AWS cost + data-classification enrichment for the inventory (INV-16/17).
 *
 * - Cost (INV-16): a per-SERVICE monthly cost summary via Cost Explorer
 *   `GetCostAndUsage`. Accurate per-resource cost isn't generally available
 *   (resource-level granularity is a paid opt-in limited to EC2), so we report an
 *   honest service-level summary rather than fabricating per-asset numbers.
 * - Data classification (INV-17): S3 buckets flagged by Macie as containing
 *   sensitive data, via `ListFindings` → `GetFindings`.
 *
 * Read-only (guardrail-wrapped clients). The pure applier lives in
 * `inventory-workbook.ts` (`applyDataClassification`) so it's unit-testable.
 */
import { GetCostAndUsageCommand } from '@aws-sdk/client-cost-explorer';
import { ListFindingsCommand, GetFindingsCommand } from '@aws-sdk/client-macie2';
import * as aws from '../../core/auth/aws.ts';

const MAX_PAGES = 50;

export interface AwsCostSummary {
  period: { start: string; end: string };
  currency: string;
  total: number;
  by_service: Record<string, number>;
  warnings: string[];
}

/** First-of-month → today (YYYY-MM-DD), the standard month-to-date window. */
function monthToDate(): { start: string; end: string } {
  const now = new Date();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString().slice(0, 10);
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1)).toISOString().slice(0, 10);
  return { start, end };
}

/** Month-to-date cost grouped by AWS service (Cost Explorer). */
export async function collectAwsCost(auth: aws.AwsAuth): Promise<AwsCostSummary> {
  const period = monthToDate();
  const by_service: Record<string, number> = {};
  const warnings: string[] = [];
  let total = 0; let currency = 'USD';
  try {
    const ce = aws.costExplorer(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await ce.send(new GetCostAndUsageCommand({
        TimePeriod: { Start: period.start, End: period.end },
        Granularity: 'MONTHLY',
        Metrics: ['UnblendedCost'],
        GroupBy: [{ Type: 'DIMENSION', Key: 'SERVICE' }],
        NextPageToken: token,
      }));
      for (const result of r.ResultsByTime ?? []) {
        for (const g of result.Groups ?? []) {
          const svc = g.Keys?.[0] ?? 'unknown';
          const amt = Number(g.Metrics?.UnblendedCost?.Amount ?? 0);
          currency = g.Metrics?.UnblendedCost?.Unit ?? currency;
          by_service[svc] = (by_service[svc] ?? 0) + amt;
          total += amt;
        }
      }
      token = r.NextPageToken && r.NextPageToken !== token ? r.NextPageToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) {
    warnings.push(`Cost Explorer (ce:GetCostAndUsage): ${e.message}`);
  }
  return { period, currency, total: Math.round(total * 100) / 100, by_service, warnings };
}

/** S3 bucket names Macie has flagged as containing sensitive data (one region). */
export async function collectMacieSensitiveBuckets(auth: aws.AwsAuth): Promise<{ buckets: Set<string>; warnings: string[] }> {
  const buckets = new Set<string>();
  const warnings: string[] = [];
  try {
    const m = aws.macie(auth);
    let token: string | undefined; let pages = 0;
    do {
      const list = await m.send(new ListFindingsCommand({
        findingCriteria: { criterion: { category: { eq: ['CLASSIFICATION'] } } },
        maxResults: 50,
        nextToken: token,
      }));
      const ids = list.findingIds ?? [];
      if (ids.length) {
        const det = await m.send(new GetFindingsCommand({ findingIds: ids }));
        for (const f of det.findings ?? []) {
          const name = f.resourcesAffected?.s3Bucket?.name;
          if (name) buckets.add(name);
        }
      }
      token = list.nextToken && list.nextToken !== token ? list.nextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) {
    // Macie not enabled / no permission is expected for many accounts.
    warnings.push(`Macie (macie2:ListFindings): ${e.message}`);
  }
  return { buckets, warnings };
}
