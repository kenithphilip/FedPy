/**
 * Per-run inventory coverage report (slice INV-S1).
 *
 * Given the normalized `CloudAsset[]` produced by the inventory pipeline,
 * walk the coverage contract (`inventory-coverage.ts`) and compute the
 * actual cell-fill rate per cloud — i.e. of the AWS assets, what fraction
 * had a non-blank "OS Name and Version", etc. The result lands at
 * `out/inventory-coverage.json` for operator + CI consumption.
 *
 * This is the structural fix that catches "assumed blank" regressions:
 * - CI can compare the report to a prior baseline and fail on regressions.
 * - The operator sees a human-readable matrix of what filled, from which API.
 * - Future enrichers don't need a separate per-cell test; this report
 *   measures the truth.
 */
import { writeFileSync } from 'node:fs';
import type { CloudAsset } from './inventory-workbook.ts';
import {
  COVERAGE_REGISTRY,
  isCellFilled,
  type ColumnCoverage,
  type CoverageReport,
  type Provider,
} from './inventory-coverage.ts';
import { log } from './log.ts';

const PROVIDERS: readonly Provider[] = ['aws', 'gcp', 'azure'];

function emptyCount(): Record<Provider, number> {
  return { aws: 0, gcp: 0, azure: 0 };
}

/**
 * Build the in-memory coverage report from the asset list.
 * Pure — no I/O.
 */
export function buildCoverageReport(assets: CloudAsset[]): CoverageReport {
  // Totals per provider.
  const totalByProvider = emptyCount();
  for (const a of assets) totalByProvider[a.provider]++;

  const columns: ColumnCoverage[] = [];
  let cellsFilledByProvider = emptyCount();

  for (const entry of COVERAGE_REGISTRY) {
    const filled = emptyCount();
    for (const a of assets) {
      if (isCellFilled(a, entry)) filled[a.provider]++;
    }
    const fillRate: Record<Provider, number> = {
      aws:   totalByProvider.aws   > 0 ? filled.aws   / totalByProvider.aws   : 0,
      gcp:   totalByProvider.gcp   > 0 ? filled.gcp   / totalByProvider.gcp   : 0,
      azure: totalByProvider.azure > 0 ? filled.azure / totalByProvider.azure : 0,
    };
    const status: Record<Provider, ColumnCoverage['status'][Provider]> = {
      aws:   entry.sources.aws.status,
      gcp:   entry.sources.gcp.status,
      azure: entry.sources.azure.status,
    };
    columns.push({
      column: entry.column,
      total: { ...totalByProvider },
      filled,
      fillRate,
      status,
      blankReason: entry.blankReason,
    });
    for (const p of PROVIDERS) cellsFilledByProvider[p] += filled[p];
  }

  const totalCells: Record<Provider, number> = {
    aws:   totalByProvider.aws   * COVERAGE_REGISTRY.length,
    gcp:   totalByProvider.gcp   * COVERAGE_REGISTRY.length,
    azure: totalByProvider.azure * COVERAGE_REGISTRY.length,
  };

  return {
    generated_at: new Date().toISOString(),
    schema_version: 1,
    columns,
    totals: {
      aws:   { assets: totalByProvider.aws,   filled_cells: cellsFilledByProvider.aws,   total_cells: totalCells.aws,   fill_rate: totalCells.aws   ? cellsFilledByProvider.aws   / totalCells.aws   : 0 },
      gcp:   { assets: totalByProvider.gcp,   filled_cells: cellsFilledByProvider.gcp,   total_cells: totalCells.gcp,   fill_rate: totalCells.gcp   ? cellsFilledByProvider.gcp   / totalCells.gcp   : 0 },
      azure: { assets: totalByProvider.azure, filled_cells: cellsFilledByProvider.azure, total_cells: totalCells.azure, fill_rate: totalCells.azure ? cellsFilledByProvider.azure / totalCells.azure : 0 },
    },
  };
}

/** Write the coverage report to disk. */
export function writeCoverageReport(report: CoverageReport, outPath: string): void {
  writeFileSync(outPath, JSON.stringify(report, null, 2));
  log.info({
    event: 'inventory_coverage.emitted',
    path: outPath,
    aws_fill: report.totals.aws.fill_rate,
    gcp_fill: report.totals.gcp.fill_rate,
    azure_fill: report.totals.azure.fill_rate,
  });
}

/**
 * Build + write in one call (used by the orchestrator).
 * Returns the in-memory report so the orchestrator can include a one-line
 * summary in its run output.
 */
export function emitInventoryCoverage(assets: CloudAsset[], outPath: string): CoverageReport {
  const report = buildCoverageReport(assets);
  writeCoverageReport(report, outPath);
  return report;
}

/**
 * Short human-friendly summary string for `console.log`.
 * Example: "Coverage: AWS 96% · GCP 84% · Azure 72% (25-column / 3-cloud × N assets)"
 */
export function coverageSummary(report: CoverageReport): string {
  const fmt = (r: number) => `${Math.round(r * 100)}%`;
  const parts: string[] = [];
  for (const p of PROVIDERS) {
    const t = report.totals[p];
    if (t.assets > 0) parts.push(`${p.toUpperCase()} ${fmt(t.fill_rate)} (${t.filled_cells}/${t.total_cells} cells, ${t.assets} assets)`);
  }
  return parts.length > 0 ? parts.join(' · ') : 'no assets';
}
