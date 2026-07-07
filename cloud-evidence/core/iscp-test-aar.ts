/**
 * Contingency Plan Test After-Action Report (AAR) emitter — LOOP-C.C2.
 *
 * Renders `iscp-test-aar.docx` — the annual Contingency Plan Test report
 * structured per the FedRAMP SSP Appendix G "Contingency Plan Test Report"
 * appendix, satisfying NIST SP 800-53 Rev. 5 control CP-4 (Contingency Plan
 * Testing). The 3PAO samples the most-recent test result alongside the ISCP
 * (iscp.docx, emitted by core/iscp-emit.ts) during the assessment cycle.
 *
 * Authoritative sources (verbatim):
 *   - NIST SP 800-53 Rev. 5 CP-4 (Contingency Plan Testing) —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final :
 *     "Test the contingency plan for the system [Assignment: organization-
 *      defined frequency] using the following tests to determine the
 *      effectiveness of the plan and the readiness to execute the plan:
 *      [Assignment: organization-defined tests]; Review the contingency plan
 *      test results; Initiate corrective actions, if needed; Coordinate
 *      contingency plan testing with organizational elements responsible for
 *      related plans."
 *   - NIST SP 800-34 Rev. 1 §3.6 — defines the tabletop, functional, and
 *     full-interruption test types (the `testType` enum values) —
 *     https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final
 *   - FedRAMP SSP Appendix G ISCP Template, Appendix F "Contingency Plan Test
 *     Report" — section structure mirrored.
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts packed with the store-only ZIP writer (core/zip.ts). The OOXML blocks
 * mirror core/iscp-emit.ts / core/cmp-emit.ts (local constants per the shipped
 * docx-emitter precedent; see LOOP-C-RISKS C-C2-10).
 *
 * REO compliance:
 *   - Test scenarios + lessons learned come ONLY from operator input — the
 *     emitter never fabricates test results. When `scenarios` is empty, a
 *     single REQUIRES-OPERATOR-INPUT row instructs the operator to populate it.
 *   - The §6 sign-off block carries REQUIRES-OPERATOR-INPUT signature/date
 *     cells; an explicit footer note states the wet/electronic signatures are
 *     captured out-of-band (the system never auto-signs a human attestation —
 *     REO Rule 1.10).
 *   - Fully deterministic (no wall-clock time): `testDate` defaults to a
 *     REQUIRES-OPERATOR-INPUT marker rather than `new Date()` (REO Rule 1.7);
 *     the metadata UUID is `deterministicUuid('iscp-test-aar:'+runId+':'+testDate)`.
 *   - When present, the report anchors itself to the ISCP it tested by citing
 *     the SHA-256 of out/iscp.docx (CP-4 ties the test to the current plan).
 *
 * Pure renderer (`renderIscpTestAarDocx` / `buildIscpTestAarBodyXml`) + disk
 * emitter (`emitIscpTestAarDocx`).
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { xmlEscape, zipStore } from './zip.ts';
import { deterministicUuid } from './oscal.ts';
import { log } from './log.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
/** Verbatim marker for missing operator input (REO Rule 4). */
const TBD = 'REQUIRES-OPERATOR-INPUT';
const TEST_TYPES = ['tabletop', 'functional', 'full-interruption'] as const;
type TestType = (typeof TEST_TYPES)[number];
const OUTCOMES = ['pass', 'fail', 'partial'] as const;
type Outcome = (typeof OUTCOMES)[number];
const HIGH_SEVERITIES = new Set(['high', 'critical']);

/** Thrown when a scenario carries an out-of-range numeric field. */
export class IscpAarValidationError extends Error {
  constructor(message: string) {
    super(`iscp-test-aar: ${message}`);
    this.name = 'IscpAarValidationError';
  }
}

// ─── OOXML building blocks (same pattern as iscp-emit.ts / cmp-emit.ts) ───────

function para(text: string, style?: string): string {
  const pPr = style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : '';
  if (text === '') return `<w:p>${pPr}</w:p>`;
  const runs = text.split('\n').map((line, i) =>
    `${i > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
  ).join('');
  return `<w:p>${pPr}<w:r>${runs}</w:r></w:p>`;
}

function heading(text: string, level: 1 | 2 | 3): string {
  return para(text, `Heading${level}`);
}

interface TableOpts { headerRow?: boolean }

function table(headers: string[], rows: string[][], widths: number[], opts: TableOpts = {}): string {
  const headerRow = opts.headerRow ?? true;
  const grid = `<w:tblGrid>${widths.map((w) => `<w:gridCol w:w="${w}"/>`).join('')}</w:tblGrid>`;
  const border = '<w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/>' +
    '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/>';
  const tblPr = `<w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders>${border}</w:tblBorders></w:tblPr>`;

  const cell = (text: string, w: number, bold: boolean, shade: boolean): string => {
    const shadeXml = shade ? '<w:shd w:val="clear" w:color="auto" w:fill="E7E6E6"/>' : '';
    const runPr = bold ? '<w:rPr><w:b/></w:rPr>' : '';
    const runs = text.split('\n').map((line, i) =>
      `${i > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
    ).join('');
    return `<w:tc><w:tcPr><w:tcW w:w="${w}" w:type="dxa"/>${shadeXml}</w:tcPr>` +
      `<w:p><w:r>${runPr}${runs}</w:r></w:p></w:tc>`;
  };

  const tr = (cells: string[], bold: boolean, shade: boolean): string =>
    `<w:tr>${cells.map((c, i) => cell(c, widths[i] ?? 2000, bold, shade)).join('')}</w:tr>`;

  const body: string[] = [];
  if (headerRow) body.push(tr(headers, true, true));
  for (const r of rows) body.push(tr(r, false, false));
  return `<w:tbl>${tblPr}${grid}${body.join('')}</w:tbl>`;
}

function fieldTable(rows: Array<[string, string]>): string {
  return table(['Field', 'Value'], rows, [3000, 6000], { headerRow: false });
}

// ─── Public options + result ─────────────────────────────────────────────────

/** A test participant (§1). */
export interface IscpTestParticipant {
  role: string;
  name: string;
  org: string;
}

/** A test scenario with RTO/RPO target-vs-actual (§2). */
export interface IscpTestScenario {
  id: string;
  description: string;
  rto_target_hours: number;
  rto_actual_hours: number;
  rpo_target_hours: number;
  rpo_actual_hours: number;
  outcome: Outcome;
}

/** A lessons-learned finding (§4). Feeds POA&M when severity is high/critical. */
export interface IscpTestLessonLearned {
  id: string;
  finding: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  recommendation: string;
  owner: string;
  due_date: string;
}

export interface IscpTestAarOptions {
  /** Where the orchestrator writes. The emitter reads iscp.docx from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/iscp-test-aar.docx). */
  outPath?: string;
  /** Run id — captured in provenance + deterministic UUID seed. */
  runId: string;
  /** FRMR catalog version — captured in provenance. */
  frmrVersion?: string;
  /** System identity (for the report header). */
  systemName?: string;
  systemId?: string;
  /** Test date (ISO). Defaults to REQUIRES-OPERATOR-INPUT — never new Date(). */
  testDate?: string;
  /** Test type (tabletop / functional / full-interruption). No default (Q5). */
  testType?: TestType;
  participants?: IscpTestParticipant[];
  scenarios?: IscpTestScenario[];
  lessonsLearned?: IscpTestLessonLearned[];
  /** §6 test coordinator (sign-off block). */
  testCoordinator?: string;
}

export interface IscpTestAarResult {
  path: string;
  bytes: number;
  scenario_count: number;
  /** Count of scenarios with outcome=fail. */
  failed_scenario_count: number;
  /** Count of lessons learned with severity high/critical (POA&M candidates). */
  poam_candidate_count: number;
  /** True when scenarios + testDate + testType are all supplied. */
  ready_for_signature: boolean;
  requires_operator_input: string[];
}

// ─── ISCP anchor (Q4: SHA-256 of the plan this test exercised) ────────────────

/** SHA-256 of out/iscp.docx when present (anchors the AAR to a plan revision). */
function iscpDigest(outDir: string): string | null {
  const p = resolve(outDir, 'iscp.docx');
  if (!existsSync(p)) return null;
  try { return createHash('sha256').update(readFileSync(p)).digest('hex'); }
  catch { return null; }
}

// ─── Validation ──────────────────────────────────────────────────────────────

function validateScenarios(scenarios: IscpTestScenario[]): void {
  for (const s of scenarios) {
    const fields: Array<[string, number]> = [
      ['rto_target_hours', s.rto_target_hours],
      ['rto_actual_hours', s.rto_actual_hours],
      ['rpo_target_hours', s.rpo_target_hours],
      ['rpo_actual_hours', s.rpo_actual_hours],
    ];
    for (const [name, val] of fields) {
      if (typeof val === 'number' && val < 0) {
        throw new IscpAarValidationError(
          `scenario "${s.id}" has a negative ${name} (${val}); recovery hours must be >= 0.`,
        );
      }
    }
    if (!OUTCOMES.includes(s.outcome)) {
      throw new IscpAarValidationError(
        `scenario "${s.id}" has an unknown outcome "${s.outcome}"; must be ${OUTCOMES.join(' | ')}.`,
      );
    }
  }
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildIscpTestAarBodyXml(opts: IscpTestAarOptions): {
  xml: string;
  stats: Omit<IscpTestAarResult, 'path' | 'bytes'>;
} {
  const scenarios = opts.scenarios ?? [];
  validateScenarios(scenarios);
  if (opts.testType && !TEST_TYPES.includes(opts.testType)) {
    throw new IscpAarValidationError(
      `unknown testType "${opts.testType}"; must be ${TEST_TYPES.join(' | ')}.`,
    );
  }

  const systemName = opts.systemName || TBD;
  const testDate = (opts.testDate && opts.testDate.trim()) ? opts.testDate : TBD;
  const testType = opts.testType ?? TBD;
  const participants = opts.participants ?? [];
  const lessons = opts.lessonsLearned ?? [];
  const poamCandidates = lessons.filter((l) => HIGH_SEVERITIES.has(l.severity));

  const missing: string[] = [];
  if (scenarios.length === 0) missing.push('scenarios');
  if (!opts.testDate || !opts.testDate.trim()) missing.push('testDate');
  if (!opts.testType) missing.push('testType');

  const failed = scenarios.filter((s) => s.outcome === 'fail');
  const passed = scenarios.filter((s) => s.outcome === 'pass');
  const partial = scenarios.filter((s) => s.outcome === 'partial');

  const docUuid = deterministicUuid(`iscp-test-aar:${opts.runId}:${testDate}`);
  const iscpSha = iscpDigest(opts.outDir);

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('Contingency Plan Test — After-Action Report', 'Title'));
  parts.push(para(`${systemName} — CP-4 Contingency Plan Testing`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-structured by fedramp-20x-cloud-evidence. Test scenarios and lessons ' +
    `learned are operator-supplied (never fabricated). Every ${TBD} marker — including the §6 ` +
    'sign-off cells — is completed out-of-band before circulation. The CSP is the author-of-record.',
    'Disclaimer',
  ));

  // ── §1 Test Overview ──
  parts.push(heading('1. Test Overview', 1));
  parts.push(para(
    'This report records the annual Contingency Plan test performed under NIST SP 800-53 ' +
    'Rev. 5 control CP-4: "Test the contingency plan for the system [Assignment: ' +
    'organization-defined frequency] ...; Review the contingency plan test results; Initiate ' +
    'corrective actions, if needed; Coordinate contingency plan testing with organizational ' +
    'elements responsible for related plans." (NIST SP 800-53 Rev. 5, CP-4)',
  ));
  parts.push(fieldTable([
    ['System Name', systemName],
    ['System ID', opts.systemId || TBD],
    ['Test Date', testDate],
    ['Test Type', testType],
    ['Test Coordinator', opts.testCoordinator || TBD],
    ['ISCP Under Test', iscpSha ? `out/iscp.docx (sha256 ${iscpSha})` : `${TBD} (emit iscp.docx with --iscp to anchor this test to a plan revision)`],
    ['Document UUID', docUuid],
    ['Run ID', opts.runId],
  ]));
  parts.push(para(
    'Test types per NIST SP 800-34 Rev. 1 §3.6: tabletop (discussion-based), functional ' +
    '(operations-based, exercising specific functions), and full-interruption (activates the ' +
    'plan against production-equivalent systems).',
  ));
  parts.push(heading('1.1 Participants', 2));
  if (participants.length > 0) {
    parts.push(table(
      ['Role', 'Name', 'Organization'],
      participants.map((p) => [p.role, p.name, p.org]),
      [3000, 3000, 3000],
    ));
  } else {
    parts.push(para(`${TBD}: list the test participants (role, name, organization).`));
  }

  // ── §2 Scenarios Executed ──
  parts.push(heading('2. Scenarios Executed', 1));
  if (scenarios.length > 0) {
    parts.push(table(
      ['ID', 'Description', 'RTO Target (h)', 'RTO Actual (h)', 'RPO Target (h)', 'RPO Actual (h)', 'Outcome'],
      scenarios.map((s) => [
        s.id,
        s.description,
        String(s.rto_target_hours),
        String(s.rto_actual_hours),
        String(s.rpo_target_hours),
        String(s.rpo_actual_hours),
        s.outcome.toUpperCase(),
      ]),
      [1200, 2600, 1200, 1200, 1200, 1200, 1000],
    ));
  } else {
    parts.push(table(
      ['ID', 'Description', 'RTO Target (h)', 'RTO Actual (h)', 'RPO Target (h)', 'RPO Actual (h)', 'Outcome'],
      [[TBD, `Operator must populate scenarios[] before circulating for signature. AAR template generated ${opts.runId}.`, '—', '—', '—', '—', TBD]],
      [1200, 2600, 1200, 1200, 1200, 1200, 1000],
    ));
  }

  // ── §3 Test Results Summary ──
  parts.push(heading('3. Test Results Summary', 1));
  parts.push(fieldTable([
    ['Scenarios Executed', String(scenarios.length)],
    ['Passed', String(passed.length)],
    ['Partial', String(partial.length)],
    ['Failed', String(failed.length)],
  ]));
  if (failed.length > 0) {
    parts.push(para(
      `FAILED scenarios requiring corrective action (CP-4.c): ${failed.map((s) => s.id).join(', ')}. ` +
      'Each failure must be tracked to closure via a POA&M item (§4/§5).',
    ));
  } else if (scenarios.length > 0) {
    parts.push(para('No failed scenarios. Any partial results are addressed in §4 Lessons Learned.'));
  }

  // ── §4 Lessons Learned ──
  parts.push(heading('4. Lessons Learned', 1));
  if (lessons.length > 0) {
    parts.push(table(
      ['ID', 'Finding', 'Severity', 'Recommendation', 'Owner', 'Due Date'],
      lessons.map((l) => [l.id, l.finding, l.severity.toUpperCase(), l.recommendation, l.owner, l.due_date]),
      [1000, 2600, 1200, 2600, 1400, 1400],
    ));
  } else {
    parts.push(para(`${TBD}: record lessons learned from the test (finding, severity, recommendation, owner, due date).`));
  }

  // ── §5 Recommendations & Action Items ──
  parts.push(heading('5. Recommendations & Action Items', 1));
  if (poamCandidates.length > 0) {
    parts.push(para(
      `The following high/critical lessons learned MUST be filed as POA&M items via the tracker ` +
      `(LOOP-A.A1): ${poamCandidates.map((l) => l.id).join(', ')}. Each is tracked to closure ` +
      'with a remediation deadline per the risk-scoring engine (LOOP-B).',
    ));
  } else if (lessons.length > 0) {
    parts.push(para(
      'No high/critical lessons learned. Address medium/low items per the CSP remediation ' +
      'schedule and re-test at the next annual cycle.',
    ));
  } else {
    parts.push(para(
      `${TBD}: summarize the corrective actions arising from the test. High/critical findings ` +
      'are filed as POA&M items via the tracker (LOOP-A.A1).',
    ));
  }

  // ── §6 Sign-off ──
  parts.push(heading('6. Sign-off', 1));
  parts.push(para(
    'The signatures below attest that the test was conducted and its results reviewed (CP-4.b). ' +
    `The signature and date cells are ${TBD}; wet or electronic signatures are captured ` +
    'out-of-band per the CSP sign-off process (the toolkit never auto-signs a human ' +
    'attestation — REO Rule 1.10). Once the tracker sign-off flow (LOOP-E.E7) lands, these ' +
    'attestations are captured there with a signed audit record.',
  ));
  const coordName = opts.testCoordinator || TBD;
  parts.push(table(
    ['Role', 'Name', 'Signature', 'Date'],
    [
      ['Test Coordinator', coordName, TBD, TBD],
      ['IT Director', TBD, TBD, TBD],
      ['System Owner', TBD, TBD, TBD],
      ['3PAO Observer', TBD, TBD, TBD],
    ],
    [2600, 2600, 2400, 1400],
  ));

  // ── Provenance ──
  parts.push(heading('Provenance', 1));
  parts.push(fieldTable([
    ['Generated By', 'fedramp-20x-cloud-evidence (core/iscp-test-aar.ts)'],
    ['Document UUID', docUuid],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion || TBD],
    ['ISCP Under Test', iscpSha ? `out/iscp.docx (sha256 ${iscpSha})` : '(none — see §1)'],
    ['Satisfies Control', 'NIST SP 800-53 Rev. 5 CP-4 (Contingency Plan Testing)'],
    ['Template Source', 'FedRAMP SSP Appendix G Appendix F + NIST SP 800-34 Rev. 1 §3.6'],
  ]));

  // ── Page geometry (US Letter) ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      scenario_count: scenarios.length,
      failed_scenario_count: failed.length,
      poam_candidate_count: poamCandidates.length,
      ready_for_signature: missing.length === 0,
      requires_operator_input: missing,
    },
  };
}

// ─── OOXML package parts ─────────────────────────────────────────────────────

function stylesXml(): string {
  const style = (id: string, name: string, o: { size?: number; bold?: boolean; color?: string; italic?: boolean; spacingBefore?: number; basedOn?: string }) => {
    const rPr = `<w:rPr>${o.bold ? '<w:b/>' : ''}${o.italic ? '<w:i/>' : ''}` +
      `${o.color ? `<w:color w:val="${o.color}"/>` : ''}` +
      `${o.size ? `<w:sz w:val="${o.size}"/>` : ''}</w:rPr>`;
    const pPr = o.spacingBefore ? `<w:pPr><w:spacing w:before="${o.spacingBefore}" w:after="120"/></w:pPr>` : '<w:pPr><w:spacing w:after="120"/></w:pPr>';
    return `<w:style w:type="paragraph" w:styleId="${id}"><w:name w:val="${name}"/>` +
      `${o.basedOn ? `<w:basedOn w:val="${o.basedOn}"/>` : ''}${pPr}${rPr}</w:style>`;
  };
  const docDefaults = '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>';
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:styles xmlns:w="${W_NS}">${docDefaults}` +
    `<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>` +
    style('Title', 'Title', { size: 56, bold: true, color: '1F3864' }) +
    style('Subtitle', 'Subtitle', { size: 30, color: '2E74B5' }) +
    style('Disclaimer', 'Disclaimer', { size: 18, italic: true, color: 'C00000' }) +
    style('Heading1', 'heading 1', { size: 32, bold: true, color: '1F3864', spacingBefore: 360 }) +
    style('Heading2', 'heading 2', { size: 26, bold: true, color: '2E74B5', spacingBefore: 240 }) +
    style('Heading3', 'heading 3', { size: 24, bold: true, color: '1F4E79', spacingBefore: 160 }) +
    `</w:styles>`;
}

/** docProps/core.xml — deterministic title metadata (no wall-clock time). */
function coreXml(systemName: string, docUuid: string): string {
  const title = `Contingency Plan Test After-Action Report — ${systemName} [${docUuid}]`;
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
    `xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" ` +
    `xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
    `<dc:title>${xmlEscape(title)}</dc:title>` +
    `<dc:creator>fedramp-20x-cloud-evidence</dc:creator>` +
    `<cp:contentStatus>DRAFT</cp:contentStatus>` +
    `</cp:coreProperties>`;
}

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
  `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
  `<Default Extension="xml" ContentType="application/xml"/>` +
  `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
  `<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
  `<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
  `</Types>`;

const ROOT_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
  `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
  `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
  `</Relationships>`;

const DOC_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
  `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
  `</Relationships>`;

/** Pure: render a Contingency Plan Test After-Action Report to a Buffer. */
export function renderIscpTestAarDocx(opts: IscpTestAarOptions): {
  buffer: Buffer;
  stats: Omit<IscpTestAarResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildIscpTestAarBodyXml(opts);
  const systemName = opts.systemName || TBD;
  const testDate = (opts.testDate && opts.testDate.trim()) ? opts.testDate : TBD;
  const docUuid = deterministicUuid(`iscp-test-aar:${opts.runId}:${testDate}`);
  const b = (s: string) => Buffer.from(s, 'utf8');
  const buffer = zipStore([
    { name: '[Content_Types].xml', data: b(CONTENT_TYPES) },
    { name: '_rels/.rels', data: b(ROOT_RELS) },
    { name: 'docProps/core.xml', data: b(coreXml(systemName, docUuid)) },
    { name: 'word/document.xml', data: b(xml) },
    { name: 'word/styles.xml', data: b(stylesXml()) },
    { name: 'word/_rels/document.xml.rels', data: b(DOC_RELS) },
  ]);
  return { buffer, stats };
}

/** Render and write iscp-test-aar.docx. */
export function emitIscpTestAarDocx(opts: IscpTestAarOptions): IscpTestAarResult {
  const { buffer, stats } = renderIscpTestAarDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'iscp-test-aar.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'iscp-test-aar.emitted',
    path: outPath,
    bytes: buffer.length,
    scenario_count: stats.scenario_count,
    failed_scenario_count: stats.failed_scenario_count,
    poam_candidate_count: stats.poam_candidate_count,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
