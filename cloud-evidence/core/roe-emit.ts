/**
 * Rules of Engagement (RoE) template seed — LOOP-A.A5.
 *
 * Renders a FedRAMP-style Rules of Engagement Word document (.docx) pre-
 * filled with the system identity, authorization-boundary scope, IP ranges
 * pulled from the real inventory, scan windows, testing authorization, and
 * escalation contacts. The 3PAO opens the document, completes the
 * remaining fields, and obtains CSP + 3PAO signatures — the RoE is
 * formally 3PAO-authored, but seeding it from real data removes the
 * "copy-the-template + transcribe-the-network-diagram" busywork.
 *
 * Why this exists:
 *   Every FedRAMP assessment begins with a signed RoE that bounds what the
 *   3PAO is authorized to test, when, against which IP ranges, and how
 *   incidents during testing escalate. The RoE is also a back-matter
 *   resource of the AP (LOOP-A.A2 emits the link). Without a seeded
 *   template, the 3PAO either copies an unrelated CSP's RoE (risking
 *   stale IPs / wrong system name) or starts from a blank FedRAMP
 *   template (manual transcription from inventory).
 *
 * Approach (dependency-free .docx):
 *   A .docx is a ZIP of WordprocessingML XML parts. We build the parts as
 *   strings and pack with the same store-only ZIP writer the SSP-2
 *   renderer uses (core/zip.ts). No external Word library, no runtime
 *   network, no operating-system tools.
 *
 * REO compliance:
 *   - System name, CSP organization, 3PAO organization, assessment
 *     period start/end, scan window times, and escalation contacts all
 *     flow through RoEEmitOptions. When any required-for-signature field
 *     is omitted, the emitter writes "REQUIRES-OPERATOR-INPUT: <field>"
 *     in the cell instead of substituting a default that looks real.
 *   - The IP-range table is derived from real inventory.json IPs/MACs —
 *     the emitter never invents addresses. If inventory is missing or
 *     empty, the table emits a single row with a
 *     REQUIRES-OPERATOR-INPUT marker explaining how to populate it.
 *   - The "controls in scope" table is derived from the registered
 *     ksi-map — one row per KSI domain. Operators see exactly what the
 *     collector will test.
 *
 * Pure renderer (`renderRoeDocx`) + disk reader/emitter (`emitRoeDocx`).
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { xmlEscape, zipStore } from './zip.ts';
import { log } from './log.ts';

const W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
const TBD = 'REQUIRES-OPERATOR-INPUT';

// ─── OOXML building blocks (same pattern as ssp-docx.ts) ─────────────────────

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

export interface RoEContact {
  /** Role in the engagement (e.g. "CSP Primary POC", "3PAO Lead Assessor"). */
  role: string;
  name: string;
  organization: string;
  /** Email + phone — both populated when known. */
  email?: string;
  phone?: string;
  /** True for incident-escalation contacts (top of the contacts table). */
  escalation?: boolean;
}

export interface RoEScanWindow {
  /** ISO-8601 start datetime (e.g. "2026-07-15T22:00:00-04:00"). */
  start: string;
  /** ISO-8601 end datetime. */
  end: string;
  /** Time-zone description for the human reading (e.g. "US/Eastern, business hours excluded"). */
  description?: string;
}

export interface RoEEmitOptions {
  /** Where the orchestrator has been writing. The emitter reads inventory.json from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/roe.docx). */
  outPath?: string;
  /** Run id — captured in the RoE footer. */
  runId: string;
  /** FRMR catalog version — captured in the RoE footer. */
  frmrVersion: string;
  /** Impact level (low/moderate/high). */
  impactLevel: 'low' | 'moderate' | 'high';
  /** System identity. */
  systemName?: string;
  systemId?: string;
  /** Operator orgs. */
  cspOrganization?: string;
  thirdPartyAssessor?: string;
  /** Operator-supplied authorization-boundary narrative. */
  authorizationBoundaryDescription?: string;
  /** Operator-supplied assessment period (ISO-8601 dates). */
  assessmentPeriodStart?: string;
  assessmentPeriodEnd?: string;
  /** Operator-supplied scan windows. */
  scanWindows?: RoEScanWindow[];
  /** Operator-supplied contacts (CSP primary, 3PAO lead, escalation). */
  contacts?: RoEContact[];
  /**
   * Override for the IP-range list. When omitted, the emitter walks
   * inventory.json and extracts every distinct IP from
   * `asset.ips[]` (with `asset.location` + `asset.assetType` context).
   * When inventory is missing or empty, a REQUIRES-OPERATOR-INPUT row is
   * emitted explaining the fix.
   */
  ipRanges?: Array<{ ip: string; description?: string }>;
  /** Optional URL where the RoE will be published once signed. */
  signedRoeHref?: string;
}

export interface RoEEmitResult {
  path: string;
  bytes: number;
  /** Count of IP rows in the table (real, not REQUIRES-OPERATOR-INPUT). */
  ip_count: number;
  /** Count of contacts. */
  contact_count: number;
  /** Count of scan-window rows. */
  scan_window_count: number;
  /** True when every required-for-signature field was operator-supplied. */
  ready_for_signature: boolean;
  /** Missing-input list for operator action. */
  requires_operator_input: string[];
}

// ─── Inventory reader ────────────────────────────────────────────────────────

function readInventoryIps(outDir: string): Array<{ ip: string; description: string }> {
  const p = resolve(outDir, 'inventory.json');
  if (!existsSync(p)) return [];
  let doc: any;
  try { doc = JSON.parse(readFileSync(p, 'utf8')); }
  catch { return []; }
  const assets: any[] = Array.isArray(doc?.assets) ? doc.assets : (Array.isArray(doc) ? doc : []);
  const out: Array<{ ip: string; description: string }> = [];
  const seen = new Set<string>();
  for (const a of assets) {
    const ips: string[] = Array.isArray(a?.ips) ? a.ips : [];
    for (const ip of ips) {
      if (typeof ip !== 'string' || !ip) continue;
      if (seen.has(ip)) continue;
      seen.add(ip);
      const ctx = [a?.assetType, a?.location, a?.provider].filter(Boolean).join(' / ');
      out.push({ ip, description: ctx || a?.uniqueId || a?.name || '(asset)' });
    }
  }
  return out;
}

// ─── KSI scope reader ────────────────────────────────────────────────────────

function readKsiScope(): Array<{ ksi: string }> {
  // Same trick the FRMR extractor + AP emitter use: grep the ksi-map source
  // so we don't depend on importing the actual map (which would pull every
  // provider module into the bundle at emit time).
  const p = resolve(import.meta.dirname ?? '', 'ksi-map.ts');
  try {
    const src = readFileSync(p, 'utf8');
    const ids = new Set<string>();
    for (const m of src.matchAll(/^\s*'(KSI-[A-Z]+-[A-Z]+)'\s*:/gm)) ids.add(m[1]!);
    return [...ids].sort().map((ksi) => ({ ksi }));
  } catch {
    return [];
  }
}

// ─── Default contacts ────────────────────────────────────────────────────────

function defaultContacts(_opts: RoEEmitOptions): RoEContact[] {
  // Per REO Rule 4, when no contacts supplied, emit a structurally-complete
  // table with REQUIRES-OPERATOR-INPUT markers so the 3PAO sees exactly
  // which roles need to be filled.
  return [
    { role: 'CSP Primary POC', name: TBD, organization: TBD, email: TBD, phone: TBD },
    { role: 'CSP Technical Lead', name: TBD, organization: TBD, email: TBD, phone: TBD },
    { role: 'CSP Incident Response Lead', name: TBD, organization: TBD, email: TBD, phone: TBD, escalation: true },
    { role: '3PAO Lead Assessor', name: TBD, organization: TBD, email: TBD, phone: TBD },
    { role: '3PAO Project Manager', name: TBD, organization: TBD, email: TBD, phone: TBD },
    { role: '3PAO Incident Escalation', name: TBD, organization: TBD, email: TBD, phone: TBD, escalation: true },
  ];
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildRoeBodyXml(opts: RoEEmitOptions): {
  xml: string;
  stats: Omit<RoEEmitResult, 'path' | 'bytes'>;
} {
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;
  const tpa = opts.thirdPartyAssessor || TBD;
  const boundary = opts.authorizationBoundaryDescription
    || `${TBD}: provide a narrative description of the authorization boundary, including in-scope components, services, data flows, and trust boundaries. Reference the boundary diagram in the SSP package.`;
  const periodStart = opts.assessmentPeriodStart || TBD;
  const periodEnd = opts.assessmentPeriodEnd || TBD;

  // Required-for-signature input tracker.
  const missing: string[] = [];
  const trackMissing = (label: string, val: string | undefined) => { if (!val) missing.push(label); };
  trackMissing('systemName', opts.systemName);
  trackMissing('systemId', opts.systemId);
  trackMissing('cspOrganization', opts.cspOrganization);
  trackMissing('thirdPartyAssessor', opts.thirdPartyAssessor);
  trackMissing('authorizationBoundaryDescription', opts.authorizationBoundaryDescription);
  trackMissing('assessmentPeriodStart', opts.assessmentPeriodStart);
  trackMissing('assessmentPeriodEnd', opts.assessmentPeriodEnd);

  // ── Header / identity block ──
  const parts: string[] = [];
  parts.push(para('Rules of Engagement', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel} Assessment`, 'Subtitle'));
  parts.push(para(
    'DRAFT — seeded by fedramp-20x-cloud-evidence from real inventory + ksi-map. ' +
    `Operator must complete every ${TBD} marker before circulating for signature. ` +
    'The 3PAO is the author-of-record for the finalized RoE.',
    'Disclaimer',
  ));

  // ── 1. System Identity ──
  parts.push(heading('1. System Identity', 1));
  parts.push(fieldTable([
    ['System Name', systemName],
    ['System ID', systemId],
    ['Impact Level', opts.impactLevel.toUpperCase()],
    ['CSP Organization', csp],
    ['3PAO Organization', tpa],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
  ]));

  // ── 2. Assessment Scope ──
  parts.push(heading('2. Assessment Scope', 1));
  parts.push(heading('2.1 Authorization Boundary', 2));
  parts.push(para(boundary));

  parts.push(heading('2.2 Controls in Scope', 2));
  parts.push(para(
    'The cloud-evidence collector will execute one assessment activity per ' +
    'registered KSI. The list below is auto-derived from cloud-evidence/core/ksi-map.ts ' +
    'and reflects the actual rules the collector will run during the assessment. ' +
    'Sampling decisions for resource-level testing live in the SAP\'s Appendix B (Sampling Methodology).',
  ));
  const ksis = readKsiScope();
  if (ksis.length > 0) {
    parts.push(table(
      ['KSI ID', 'Family'],
      ksis.map((k) => [k.ksi, k.ksi.split('-')[1] ?? '']),
      [4500, 4500],
    ));
  } else {
    parts.push(table(
      ['KSI ID', 'Family'],
      [[`${TBD}: ksi-map.ts could not be read at emit time`, '']],
      [4500, 4500],
    ));
  }

  // ── 3. Assessment Period + Scan Windows ──
  parts.push(heading('3. Assessment Period & Scan Windows', 1));
  parts.push(fieldTable([
    ['Assessment Start Date', periodStart],
    ['Assessment End Date', periodEnd],
  ]));
  parts.push(heading('3.1 Authorized Scan Windows', 2));
  const scanWindows = opts.scanWindows ?? [];
  if (scanWindows.length > 0) {
    parts.push(table(
      ['Start', 'End', 'Description'],
      scanWindows.map((w) => [w.start, w.end, w.description ?? '']),
      [2700, 2700, 3600],
    ));
  } else {
    parts.push(table(
      ['Start', 'End', 'Description'],
      [[
        `${TBD}: scan window start (ISO-8601)`,
        `${TBD}: scan window end (ISO-8601)`,
        `${TBD}: description (e.g., "US/Eastern, off-peak only")`,
      ]],
      [2700, 2700, 3600],
    ));
    missing.push('scanWindows[]');
  }

  // ── 4. In-Scope IP Ranges (auto-derived) ──
  parts.push(heading('4. In-Scope Network Addresses', 1));
  parts.push(para(
    'The IP addresses below were auto-derived from out/inventory.json. ' +
    'Every address represents a real cloud resource discovered by the collector. ' +
    'The 3PAO may narrow this list via sampling per the SAP\'s Appendix B, but the ' +
    'POPULATION of in-scope addresses is exactly what appears here. Addresses NOT in ' +
    'this list are out of scope unless the 3PAO and CSP agree in writing.',
  ));
  const ipRows = opts.ipRanges ?? readInventoryIps(opts.outDir);
  if (ipRows.length > 0) {
    parts.push(table(
      ['IP / CIDR', 'Asset Context'],
      ipRows.map((r) => [r.ip, r.description ?? '']),
      [3000, 6000],
    ));
  } else {
    parts.push(table(
      ['IP / CIDR', 'Asset Context'],
      [[`${TBD}`, 'inventory.json missing or empty. Run the orchestrator with --inventory-workbook first, OR pass ipRanges via RoEEmitOptions.']],
      [3000, 6000],
    ));
    missing.push('ipRanges (inventory.json empty)');
  }

  // ── 5. Testing Authorization ──
  parts.push(heading('5. Testing Authorization', 1));
  parts.push(para(
    'The CSP authorizes the 3PAO to perform the following testing activities ' +
    'within the assessment period + scan windows defined above:',
  ));
  parts.push(table(
    ['Activity', 'Authorized', 'Constraints'],
    [
      ['Read-only inventory enumeration via cloud SDK APIs', 'Yes', 'Read-only IAM role mandated by REO + Proxy guardrails.'],
      ['Authenticated vulnerability scans (OS, web, DB)', 'Yes', 'Within authorized scan windows; results inform LOOP-A.A1 POA&M.'],
      ['Unauthenticated external port/service scans', 'Yes', 'External attack-surface only; in-boundary internal scans are authenticated.'],
      ['Configuration capture via Resource Graph / Asset Inventory', 'Yes', 'Continuous, read-only.'],
      ['Penetration testing (CA-8)', `${TBD}: Yes/No per CSP risk acceptance`, 'Scope, rules of engagement, and rollback authority TBD.'],
      ['Social engineering / phishing simulation', `${TBD}: Yes/No`, 'Typically OUT of scope unless CSP explicitly authorizes.'],
      ['Production data exfiltration (proof of impact)', 'No', 'Prohibited. Use synthetic test data; document any incidental exposure immediately.'],
      ['Denial-of-Service testing', 'No', 'Prohibited.'],
    ],
    [3500, 2000, 3500],
  ));

  // ── 6. Out of Scope / Prohibited Activities ──
  parts.push(heading('6. Out of Scope / Prohibited Activities', 1));
  parts.push(para(
    'Any activity not explicitly authorized above is OUT OF SCOPE. ' +
    'The 3PAO MUST obtain written CSP approval before performing any of the following:',
  ));
  parts.push(para('• Live exploitation of identified vulnerabilities against production systems'));
  parts.push(para('• Testing against systems NOT listed in Section 4 IP ranges'));
  parts.push(para('• Testing outside authorized scan windows (Section 3.1)'));
  parts.push(para('• Capture of cardholder data, PII, or classified information'));
  parts.push(para('• Denial-of-service or any disruption of production availability'));

  // ── 7. Escalation Contacts ──
  parts.push(heading('7. Escalation Contacts', 1));
  parts.push(para(
    'Incidents discovered during testing, scope-creep questions, and authorization ' +
    'changes are escalated immediately via the contacts below. Escalation contacts (marked ⚡) ' +
    'are available 24/7 for the duration of the assessment.',
  ));
  const contacts = (opts.contacts && opts.contacts.length > 0) ? opts.contacts : defaultContacts(opts);
  parts.push(table(
    ['Role', 'Name', 'Organization', 'Email', 'Phone'],
    contacts.map((c) => [
      (c.escalation ? '⚡ ' : '') + c.role,
      c.name,
      c.organization,
      c.email ?? TBD,
      c.phone ?? TBD,
    ]),
    [2200, 1800, 1800, 2000, 1700],
  ));

  // ── 8. Incident Handling During Testing ──
  parts.push(heading('8. Incident Handling During Testing', 1));
  parts.push(para(
    'If the 3PAO discovers an active compromise, mass-PII exposure, or any condition ' +
    'requiring immediate CSP action, the 3PAO will:',
  ));
  parts.push(para('1. Suspend testing on the affected component immediately.'));
  parts.push(para('2. Notify the CSP Incident Response Lead within 1 hour (Section 7).'));
  parts.push(para('3. Preserve evidence per FedRAMP Incident Communications Procedures (AFR-ICP).'));
  parts.push(para('4. Document the discovery in the Findings Tracker; the finding flows to LOOP-A.A1 POA&M after triage.'));
  parts.push(para('5. Resume testing only after written CSP authorization.'));

  // ── 9. Signature Block ──
  parts.push(heading('9. Signatures', 1));
  parts.push(para(
    'By signing below, the CSP and 3PAO acknowledge the scope, period, ' +
    'authorized activities, and escalation procedures defined in this Rules of Engagement.',
  ));
  parts.push(table(
    ['Party', 'Name & Title', 'Signature', 'Date'],
    [
      [`CSP — ${csp}`, TBD, TBD, TBD],
      [`3PAO — ${tpa}`, TBD, TBD, TBD],
    ],
    [2500, 2500, 2500, 1500],
  ));

  // ── 10. Provenance / footer ──
  parts.push(heading('10. Document Provenance', 1));
  parts.push(fieldTable([
    ['Generated By', 'fedramp-20x-cloud-evidence (core/roe-emit.ts)'],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
    ['Inventory Source', existsSync(resolve(opts.outDir, 'inventory.json')) ? 'out/inventory.json' : '(none — see Section 4)'],
    ['Published RoE URL', opts.signedRoeHref ?? `${TBD}: post-signature URL (links from AP back-matter once published)`],
  ]));

  // ── Page geometry ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      ip_count: ipRows.length,
      contact_count: contacts.length,
      scan_window_count: scanWindows.length,
      ready_for_signature: missing.length === 0,
      requires_operator_input: missing,
    },
  };
}

function stylesXml(): string {
  const style = (id: string, name: string, opts: { size?: number; bold?: boolean; color?: string; italic?: boolean; spacingBefore?: number; basedOn?: string }) => {
    const rPr = `<w:rPr>${opts.bold ? '<w:b/>' : ''}${opts.italic ? '<w:i/>' : ''}` +
      `${opts.color ? `<w:color w:val="${opts.color}"/>` : ''}` +
      `${opts.size ? `<w:sz w:val="${opts.size}"/>` : ''}</w:rPr>`;
    const pPr = opts.spacingBefore ? `<w:pPr><w:spacing w:before="${opts.spacingBefore}" w:after="120"/></w:pPr>` : '<w:pPr><w:spacing w:after="120"/></w:pPr>';
    return `<w:style w:type="paragraph" w:styleId="${id}"><w:name w:val="${name}"/>` +
      `${opts.basedOn ? `<w:basedOn w:val="${opts.basedOn}"/>` : ''}${pPr}${rPr}</w:style>`;
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

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
  `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
  `<Default Extension="xml" ContentType="application/xml"/>` +
  `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
  `<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
  `</Types>`;

const ROOT_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
  `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
  `</Relationships>`;

const DOC_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
  `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
  `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
  `</Relationships>`;

/** Pure: render an RoE Word document to a Buffer. */
export function renderRoeDocx(opts: RoEEmitOptions): {
  buffer: Buffer;
  stats: Omit<RoEEmitResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildRoeBodyXml(opts);
  const b = (s: string) => Buffer.from(s, 'utf8');
  const buffer = zipStore([
    { name: '[Content_Types].xml', data: b(CONTENT_TYPES) },
    { name: '_rels/.rels', data: b(ROOT_RELS) },
    { name: 'word/document.xml', data: b(xml) },
    { name: 'word/styles.xml', data: b(stylesXml()) },
    { name: 'word/_rels/document.xml.rels', data: b(DOC_RELS) },
  ]);
  return { buffer, stats };
}

/** Read inventory + ksi-map, render, and write roe.docx. */
export function emitRoeDocx(opts: RoEEmitOptions): RoEEmitResult {
  const { buffer, stats } = renderRoeDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'roe.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'roe.emitted',
    path: outPath,
    bytes: buffer.length,
    ip_count: stats.ip_count,
    contact_count: stats.contact_count,
    scan_window_count: stats.scan_window_count,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
