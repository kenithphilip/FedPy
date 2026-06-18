/**
 * Reads subprocessor inventory from a Google Sheet (per locked decision).
 * Authenticates via ADC; the runner needs Viewer access on the spreadsheet.
 *
 * Configure via config.yaml:
 *   subprocessors:
 *     spreadsheet_id: <ID>
 *     sheet_range: "Sheet1!A1:Z"
 *     columns:
 *       name: 0
 *       role: 1
 *       data_categories: 2
 *       fedramp_authorized: 3
 *       attestation_doc_url: 4
 *       soc2_expiry: 5
 *       contract_review_date: 6
 *       in_scope_for_csi: 7
 *
 * Used by:
 *   - SCR-MIT (feeds the subprocessor inventory finding)
 *   - IAM-AAM (tags external identities with subprocessor=<name>)
 */
import * as gcpAuth from './auth/gcp.ts';
import { screenSubprocessorRows } from './prohibited-vendors-screen.ts';
import type { ProhibitedVendorIndex, ProhibitedVendorMatch } from './prohibited-vendors-screen.ts';
import type { VendorNameNormalizer } from './vendor-name-normalizer.ts';

export interface SubprocessorRow {
  // ── existing fields (preserve) ──
  name: string;
  role?: string;
  data_categories?: string[];
  fedramp_authorized?: 'yes' | 'no' | 'equivalency-attest';
  attestation_doc_url?: string;
  soc2_expiry?: string;
  contract_review_date?: string;
  in_scope_for_csi?: boolean;
  // ── LOOP-J.J2 SA-9 additions (NIST SP 800-53 Rev 5 SA-9 + 800-161 Rev 1) ──
  /** Supplier risk tier (NIST SP 800-161 Rev 1 §2.3.5 tiered supplier identification). */
  risk_tier?: 'tier-1-critical' | 'tier-2-significant' | 'tier-3-routine';
  /** Processing/storage/service location (SA-9(5)). Free-form (region code or geography). */
  data_residency?: string;
  /** Date of the most recent oversight audit (drives the SSP leveraged-authorization date-authorized). */
  last_audit_date?: string;
  /** Ongoing-monitoring processes/methods/techniques (SA-9.c). */
  monitoring_methods?: string[];
  /** Contractual incident-notification SLA in hours. */
  incident_notification_sla_hours?: number;
  /** Immediate downstream subprocessors-of-this-subprocessor (flat list of names). */
  subprocessor_subprocessors?: string[];
  /** NIST 800-53 control IDs the provider contractually implements (SA-9.a). */
  contracted_controls?: string[];
  /** UUID of the organizational party that owns oversight of this provider (SA-9.b). */
  oversight_party_uuid?: string;
  /** Operator narrative of organizational oversight roles/responsibilities (SA-9.b). */
  user_roles_responsibilities?: string;
  /** Which surface this row came from (provenance). */
  source?: 'google-sheet' | 'yaml-config' | 'json-config';
  /** Source locator: `<spreadsheet_id>!<sheet_range>` for sheets, absolute path for files. */
  source_ref?: string;
}

export interface SheetConfig {
  spreadsheet_id: string;
  sheet_range: string;
  columns: {
    name: number;
    role?: number;
    data_categories?: number;
    fedramp_authorized?: number;
    attestation_doc_url?: number;
    soc2_expiry?: number;
    contract_review_date?: number;
    in_scope_for_csi?: number;
  };
}

export async function readSubprocessors(cfg: SheetConfig): Promise<{ rows: SubprocessorRow[]; warnings: string[] }> {
  const warnings: string[] = [];
  const sheets = await gcpAuth.googleClient<any>('sheets', 'v4');
  try {
    const r = await sheets.spreadsheets.values.get({
      spreadsheetId: cfg.spreadsheet_id,
      range: cfg.sheet_range,
    });
    const values: any[][] = r.data.values ?? [];
    // Skip header row
    const dataRows = values.slice(1);
    const rows: SubprocessorRow[] = dataRows
      .filter((row) => row[cfg.columns.name])
      .map((row) => {
        const get = (idx?: number) => idx === undefined ? undefined : (row[idx] ?? undefined);
        const fa = get(cfg.columns.fedramp_authorized)?.toLowerCase?.();
        const inScope = get(cfg.columns.in_scope_for_csi)?.toLowerCase?.();
        return {
          name: String(row[cfg.columns.name]),
          role: get(cfg.columns.role),
          data_categories: get(cfg.columns.data_categories)?.split(/[,;]\s*/),
          fedramp_authorized: ['yes','no','equivalency-attest'].includes(fa ?? '') ? fa as any : undefined,
          attestation_doc_url: get(cfg.columns.attestation_doc_url),
          soc2_expiry: get(cfg.columns.soc2_expiry),
          contract_review_date: get(cfg.columns.contract_review_date),
          in_scope_for_csi: inScope === 'true' || inScope === 'yes' || inScope === '1' ? true :
                            inScope === 'false' || inScope === 'no' || inScope === '0' ? false : undefined,
          // LOOP-J.J2: stamp provenance so every emitted row is self-describing.
          source: 'google-sheet',
          source_ref: `${cfg.spreadsheet_id}!${cfg.sheet_range}`,
        };
      });
    return { rows, warnings };
  } catch (e: any) {
    warnings.push(`Sheets read failed: ${e.message}`);
    return { rows: [], warnings };
  }
}

/**
 * LOOP-W.W2: screen the subprocessor rows' `name` (and any other identifying
 * field) against the prohibited-vendor catalog index. A thin wrapper over
 * `core/prohibited-vendors-screen.ts:screenSubprocessorRows` so the W.W2 screen
 * can treat the subprocessor sheet as one of its four surfaces without
 * duplicating the existing sheet-reading paths above (which stay untouched).
 */
export function screenAgainstProhibitedVendors(
  rows: SubprocessorRow[],
  index: ProhibitedVendorIndex,
  normalizer: VendorNameNormalizer,
  discoveredAt: string,
): ProhibitedVendorMatch[] {
  return screenSubprocessorRows({ rows, index, normalizer, discoveredAt });
}
