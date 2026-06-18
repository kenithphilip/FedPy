/**
 * Operator-readable `.xlsx` renderer for the prohibited-vendor screen result
 * (LOOP-W.W2). Composes the multi-sheet OOXML writer from
 * `core/supply-chain-risk.ts` (REO: compose, do not re-implement the OOXML
 * plumbing). Three sheets: Matches (one row per match), Surfaces Screened, and
 * Summary.
 */
import { multiSheetXlsx } from './supply-chain-risk.ts';
import type { ProhibitedVendorScreenResult, ProhibitedVendorMatch } from './prohibited-vendors-screen.ts';

const MATCH_HEADERS = [
  'Match ID', 'Surface', 'Catalog Source', 'Matched Entity Name', 'Confidence',
  'Confidence Band', 'Matched By', 'Match Path', 'Surface Evidence', 'POA&M Item UUID',
  'Statutory Authority', 'Discovered At', 'Suppressed', 'Suppression Justification',
  'Supplier UEI', 'Supplier CAGE', 'Brand', 'Model', 'Item Description',
];

function matchRow(m: ProhibitedVendorMatch): string[] {
  const far = m.far_52_204_25_d_data_elements;
  return [
    m.match_id,
    m.surface,
    m.catalog_provenance.source,
    m.matched_entity_name,
    m.confidence.toFixed(2),
    m.confidence_band,
    m.matched_by,
    m.match_path.join(' -> '),
    m.sources.surface_evidence,
    m.poam_item_uuid,
    m.catalog_provenance.citation,
    m.discovered_at,
    m.suppressed ? 'yes' : 'no',
    m.suppression_justification ?? '',
    far.supplier_uei,
    far.supplier_cage_code,
    far.brand,
    far.model_number,
    far.item_description,
  ];
}

/** Render the screen result to a 3-sheet `.xlsx` Buffer. */
export function screenResultToXlsx(result: ProhibitedVendorScreenResult): Buffer {
  const matchesSheet = {
    name: 'Matches',
    headers: MATCH_HEADERS,
    rows: result.matches.map(matchRow),
  };

  const surfacesSheet = {
    name: 'Surfaces Screened',
    headers: ['Surface', 'Entries Screened', 'Source Path', 'Walked At'],
    rows: result.surfaces_screened.map((s) => [
      s.surface, String(s.entries_screened), s.source_path, s.walked_at,
    ]),
  };

  const summaryRows: string[][] = [
    ['Total matches', String(result.summary.total_matches)],
    ['Suppressed matches', String(result.summary.suppressed_matches)],
    ['Catalog age (hours)', result.catalog_snapshot_ref.age_hours.toFixed(2)],
    ['Catalog stale (>24h)', result.catalog_snapshot_ref.is_stale ? 'yes' : 'no'],
    ['Reportable under FAR 52.204-25(d)', result.reportable_under_far_52_204_25_d ? 'yes' : 'no'],
    ['Reportable under NDAA 1634', result.reportable_under_ndaa_1634 ? 'yes' : 'no'],
    ['Reasonable inquiry attested', result.reasonable_inquiry_attested ? 'yes' : 'no'],
    ['', ''],
    ['By confidence band', ''],
    ['  high', String(result.summary.matches_by_confidence_band.high)],
    ['  medium', String(result.summary.matches_by_confidence_band.medium)],
    ['  low', String(result.summary.matches_by_confidence_band.low)],
    ['', ''],
    ['By catalog source', ''],
    ...Object.entries(result.summary.matches_by_source).map(([k, v]) => [`  ${k}`, String(v)]),
    ['', ''],
    ['By surface', ''],
    ...Object.entries(result.summary.matches_by_surface).map(([k, v]) => [`  ${k}`, String(v)]),
  ];
  const summarySheet = { name: 'Summary', headers: ['Metric', 'Value'], rows: summaryRows };

  return multiSheetXlsx([matchesSheet, surfacesSheet, summarySheet]);
}
