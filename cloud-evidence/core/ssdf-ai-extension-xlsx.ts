/**
 * XLSX renderer for the NIST SP 800-218A SSDF-AI extension (LOOP-T.T5).
 *
 * Composes the dependency-free OOXML/zip-store writer `multiSheetXlsx`
 * (core/supply-chain-risk.ts) — REO: compose, never re-implement the zip plumbing.
 * Produces an operator workbook with:
 *   - Summary            — per-product roll-up counts
 *   - <product>          — one worksheet per in-scope product (columns A..O per §5.3)
 *   - IPD vs final delta — augmentation-id level diff between the two catalogues
 *   - Statutory lineage  — EO 14028 → EO 14110 → SP 800-218A → OMB M-26-05 FAQ (§10 Q4)
 */
import { multiSheetXlsx } from './supply-chain-risk.ts';
import {
  type SsdfAiAugmentationResult,
  type SsdfAiAugmentationCatalogue,
  type AugmentedProductMatrix,
  EO_LINEAGE,
} from './ssdf-ai-extension.ts';

interface DeltaShape {
  ipd_augmentation_count?: number;
  final_augmentation_count?: number;
  added?: Array<{ augmentation_id: string; final_text?: string }>;
  removed?: Array<{ augmentation_id: string; ipd_text?: string }>;
  restated?: Array<{ augmentation_id: string; ipd_text?: string; final_text?: string }>;
  renamed?: Array<{ augmentation_id: string; ipd_parent?: string; final_parent?: string }>;
}

/** Excel worksheet names cap at 31 chars and forbid : \ / ? * [ ]. */
function safeSheetName(raw: string, fallback: string): string {
  const cleaned = (raw || fallback).replace(/[:\\/?*[\]]/g, '-').slice(0, 31).trim();
  return cleaned || fallback;
}

function productSheet(p: AugmentedProductMatrix): { name: string; headers: string[]; rows: string[][] } {
  const headers = [
    'Practice Group', // A
    'Parent Task ID', // B
    'Augmentation ID', // C
    'Augmentation Statement', // D
    'AI Model Risks Addressed', // E
    'Applies To', // F
    'Status', // G
    'Derivation', // H
    'Derivation Explanation', // I
    'KSI Envelope Hashes', // J
    'Model Card Pointer', // K
    'AI Evaluation Report Pointers', // L
    'Red-Team Engagement Pointers', // M
    'Training-Data Provenance Pointer', // N
    'Informative References', // O
  ];
  const rows: string[][] = [];
  for (const pr of p.practices) {
    for (const t of pr.tasks) {
      for (const a of t.augmentations) {
        rows.push([
          `${pr.practice_group} — ${pr.practice_group_name}`,
          t.parent_task_id,
          a.augmentation_id,
          a.statement,
          a.notes,
          a.applies_to.join(', '),
          a.status,
          a.derivation,
          a.derivation_explanation,
          a.evidence_pointers.ksi_envelope_hashes.join('; '),
          a.evidence_pointers.model_card_pointer ?? '',
          a.evidence_pointers.ai_evaluation_report_pointers.join('; '),
          a.evidence_pointers.red_team_engagement_pointers.join('; '),
          a.evidence_pointers.training_data_provenance_pointer ?? '',
          a.informative_references.join('; '),
        ]);
      }
    }
  }
  return { name: safeSheetName(p.product_id, 'product'), headers, rows };
}

/** Render the full T.T5 workbook to a `.xlsx` Buffer. */
export function renderAiAugmentationXlsx(
  result: SsdfAiAugmentationResult,
  catalogue: SsdfAiAugmentationCatalogue,
  delta: unknown,
): Buffer {
  const d = (delta ?? {}) as DeltaShape;

  // 1. Summary worksheet.
  const summaryHeaders = [
    'Product', 'AI Use Case', 'Dual-Use Foundation Model', 'AI-Specific Evidence Count',
    'Augmentations Evaluated', 'Satisfied', 'Partially Satisfied', 'Not Satisfied',
    'Not Assessed', 'Requires Operator Input', 'Not Applicable',
  ];
  const summaryRows: string[][] = result.products_in_scope.map((p) => {
    let evaluated = 0, sat = 0, part = 0, notSat = 0, notAssessed = 0, roi = 0, na = 0;
    for (const pr of p.practices) for (const t of pr.tasks) for (const a of t.augmentations) {
      evaluated++;
      if (a.status === 'satisfied') sat++;
      else if (a.status === 'partially-satisfied') part++;
      else if (a.status === 'not-satisfied') notSat++;
      else if (a.status === 'not-assessed') notAssessed++;
      else if (a.status === 'requires-operator-input') roi++;
      else if (a.status === 'not-applicable') na++;
    }
    return [
      p.product_id, p.ai_use_case, p.is_dual_use_foundation_model ? 'yes' : 'no', String(p.ai_specific_evidence_count),
      String(evaluated), String(sat), String(part), String(notSat), String(notAssessed), String(roi), String(na),
    ];
  });
  // Out-of-scope products appended for operator visibility.
  for (const o of result.products_out_of_scope) {
    summaryRows.push([o.product_id, `(out of scope: ${o.reason})`, '', '', '', '', '', '', '', '', '']);
  }

  const sheets: Array<{ name: string; headers: string[]; rows: string[][] }> = [
    { name: 'Summary', headers: summaryHeaders, rows: summaryRows },
  ];

  // 2. Per-product worksheets (dedupe sheet names — Excel forbids duplicates).
  const usedNames = new Set<string>(['Summary']);
  for (const p of result.products_in_scope) {
    let s = productSheet(p);
    let name = s.name;
    let i = 2;
    while (usedNames.has(name)) { name = safeSheetName(`${s.name}-${i}`, `product-${i}`); i++; }
    usedNames.add(name);
    sheets.push({ name, headers: s.headers, rows: s.rows });
  }

  // 3. IPD vs final delta worksheet.
  const deltaHeaders = ['Augmentation ID', 'Diff Class', 'IPD Text', 'Final Text', 'Parent (IPD→Final)'];
  const deltaRows: string[][] = [];
  for (const r of d.added ?? []) deltaRows.push([r.augmentation_id, 'added', '', r.final_text ?? '', '']);
  for (const r of d.removed ?? []) deltaRows.push([r.augmentation_id, 'removed', r.ipd_text ?? '', '', '']);
  for (const r of d.restated ?? []) deltaRows.push([r.augmentation_id, 'restated', r.ipd_text ?? '', r.final_text ?? '', '']);
  for (const r of d.renamed ?? []) deltaRows.push([r.augmentation_id, 'renamed', '', '', `${r.ipd_parent ?? ''} → ${r.final_parent ?? ''}`]);
  sheets.push({ name: 'IPD vs final delta', headers: deltaHeaders, rows: deltaRows });

  // 4. Statutory-lineage FAQ worksheet (§10 Q4).
  const faqRows: string[][] = [
    ['Catalogue version used', result.catalogue_version],
    ['Catalogue source PDF SHA-256', result.catalogue_sha256],
    ['NIST publication', `${catalogue.publication.sp} — ${catalogue.publication.title} (${catalogue.publication.publication_date})`],
    ['', ''],
    ['Statutory lineage', ''],
    ...EO_LINEAGE.map((step, i) => [`  ${i + 1}.`, step]),
    ['', ''],
    ['Note', 'EO 14110 was rescinded by EO 14148 (2025-01-20). NIST SP 800-218A has NOT been withdrawn and remains the canonical AI-extension catalogue cited by agency tailored regimes under OMB M-26-05. The augmentation statements in this workbook are reproduced verbatim from the pinned NIST PDF; new AI-specific evidence collection (model evaluations, red-team, training-data provenance) is produced by LOOP-O, not by this extension.'],
  ];
  sheets.push({ name: 'Statutory lineage', headers: ['Field', 'Value'], rows: faqRows });

  return multiSheetXlsx(sheets);
}
