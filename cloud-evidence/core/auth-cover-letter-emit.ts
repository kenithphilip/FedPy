/**
 * Authorization request cover letter emitter — LOOP-C.C8.
 *
 * Renders `auth-request-cover-letter.docx` — the CSP-side formal cover letter
 * (package transmittal) that accompanies a FedRAMP authorization package when it
 * is transmitted to the FedRAMP PMO or an agency Authorizing Official. It
 * satisfies NIST SP 800-53 Rev. 5 control PM-10 (Authorization Process): the CSP
 * formally requests an authorization decision, enumerates the package contents,
 * identifies the 3PAO, and lists the key contacts. It is DISTINCT from the AO's
 * ATO letter (which the FedRAMP-published ATO Letter Template covers) — that
 * letter is the AO's RESPONSE to this cover letter.
 *
 * The document auto-links to the run's real submission artifacts:
 *   - §4 Package Contents ← out/INDEX.json (LOOP-A.A4 submission-bundle) — every
 *     artifact enumerated with role + sha256-short + bytes. When INDEX.json is
 *     absent §4 degrades to a REQUIRES-OPERATOR-INPUT marker (Open Q of Risk 1;
 *     the chicken/egg of Q1 is why the letter cites per-artifact SHA-256s, not
 *     the bundle-tarball SHA-256 — the letter ships INSIDE the tarball).
 *   - §3 3PAO Statement ← out/ap.json (LOOP-A.A2 OSCAL Assessment Plan) metadata:
 *     the assessing 3PAO organization + the AP finalization date. The lead
 *     assessor + operator-preferred 3PAO name come from operator config (the AP
 *     metadata carries organization parties, not a named lead). When neither the
 *     operator nor ap.json supplies a 3PAO, §3 degrades to REQUIRES-OPERATOR-INPUT
 *     (Risk 3).
 *
 * Authoritative sources (cited in the body + the provenance footer):
 *   - NIST SP 800-53 Rev. 5 — PM-10 Authorization Process —
 *     https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — control text (§1).
 *   - NIST SP 800-37 Rev. 2 (2018-12) — RMF, §3.6 Authorize step —
 *     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf.
 *   - FedRAMP Agency Authorization Playbook v4.1 (2025-11-17) —
 *     https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf
 *     — §3 formal-request structure (letterhead → addressee → request → package
 *     summary → signatures) drives the section layout.
 *   - FedRAMP Initial Authorization Package Checklist —
 *     https://www.fedramp.gov/assets/resources/templates/FedRAMP-Initial-Authorization-Package-Checklist.xlsx
 *     — the §4 Package Contents table mirrors this checklist plus real INDEX.json
 *     sha256 values.
 *   - FedRAMP ATO Letter Template —
 *     https://www.fedramp.gov/assets/resources/templates/FedRAMP-ATO-Letter-Template.docx
 *     — the counterpart the AO returns; §5 references the expected ATO response.
 *
 * Approach (dependency-free .docx): a `.docx` is a ZIP of WordprocessingML XML
 * parts built as strings and packed with the store-only ZIP writer the shipped
 * docx emitters use (core/zip.ts) — no external Word library, no runtime network.
 * The OOXML building blocks mirror rms-emit.ts / conmon-strategy-emit.ts; the
 * shared docx-primitives module proposed in LOOP-C-SPEC §4 was never extracted
 * (LOOP-C-RISKS C-X-1 / C-C1-6..C-C7-8), so this emitter keeps its OOXML constants
 * local like its siblings — now the fourteenth emitter to migrate when C-X-1 lands.
 *
 * REO compliance:
 *   - §4 Package Contents traces to the real on-disk INDEX.json rows — no
 *     synthetic artifacts; the sha256-short values are the first 12 hex chars of
 *     the real per-artifact sha256; the row count is the real artifact count.
 *   - §3 3PAO org + AP date trace to the run's real ap.json metadata when present.
 *   - §5 Requested Action language is templated but contains no fabricated
 *     commitments from the AO side.
 *   - Operator identity fields (exec signatory, CSP address, AO addressee, 3PAO
 *     lead) are operator-supplied; absent → a REQUIRES-OPERATOR-INPUT marker
 *     (REO Rule 4). The exec signature block is never auto-signed (Risk 6).
 *   - Deterministic (no wall-clock time): the metadata UUID is
 *     `deterministicUuid('auth-cover-letter:' + systemId + ':' + runId)` and the
 *     date line resolves from submissionDate → an ISO date embedded in runId → a
 *     REQUIRES-OPERATOR-INPUT "dated at signing" marker (Risk 4). The provenance
 *     footer cites the INDEX.json + ap.json content SHA-256s, so identical inputs
 *     produce a byte-identical .docx. Integrity is anchored by the signed
 *     submission-bundle INDEX.json (SHA-256 + Ed25519), the same coverage the
 *     sibling docx receive.
 *
 * Pure renderer (`renderAuthCoverLetterDocx` / `buildCoverLetterBodyXml`) + disk
 * emitter (`emitAuthCoverLetterDocx`). The readers (`readIndexJson`,
 * `readApMetadata`) are exported for unit testing.
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

// ─── Pinned authoritative-source constants (published — REO Rule 3) ──────────

const SP_800_53_URL = 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final';
const SP_800_37_URL = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf';
const PLAYBOOK_URL = 'https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf';
const CHECKLIST_URL = 'https://www.fedramp.gov/assets/resources/templates/FedRAMP-Initial-Authorization-Package-Checklist.xlsx';
const ATO_TEMPLATE_URL = 'https://www.fedramp.gov/assets/resources/templates/FedRAMP-ATO-Letter-Template.docx';

/** NIST SP 800-53 Rev. 5 PM-10(a) — verbatim (the authorization process the cover letter enters). */
const PM_10_QUOTE =
  'Manage the security and privacy state of organizational systems and the environments in ' +
  'which those systems operate through authorization processes.';

// ─── Types ───────────────────────────────────────────────────────────────────

/** Requested authorization action (§2). */
export type AtoRequestType = 'initial-ato' | 'continued-ato' | 'reauthorization';

/** §7 CSP executive signatory (operator-supplied; never auto-signed — Risk 6). */
export interface CspExecutiveSignatory {
  name: string;
  title: string;
  email: string;
  phone?: string;
}

/** §3 / §6 3PAO lead assessor (operator-supplied; the AP metadata carries only orgs). */
export interface ThirdPartyAssessorLead {
  name: string;
  title?: string;
  email?: string;
}

/** Addressee block — the AO (or PMO) the package is transmitted to (operator-supplied). */
export interface AoAddressee {
  name: string;
  title: string;
  agency: string;
  address: string;
  /** Optional delegated authorizing-official designate (Risk 5). */
  designee?: string;
}

export interface AuthCoverLetterOptions {
  /** Where the orchestrator writes. The emitter reads INDEX.json + ap.json from here. */
  outDir: string;
  /** Output path (defaults to <outDir>/auth-request-cover-letter.docx). */
  outPath?: string;
  /** Run id — captured in the provenance (§1) + deterministic UUID seed + date fallback. */
  runId: string;
  /** FRMR catalog version — captured in the provenance (§1). */
  frmrVersion: string;
  /** System identity (reuses --system-name / --system-id / --oscal-org). */
  systemName?: string;
  systemId?: string;
  cspOrganization?: string;
  /** §Letterhead CSP mailing address (config.yaml: org.address). */
  cspAddress?: string;
  /** §7 exec signatory (config.yaml: auth_request.executive_signatory). */
  cspExecutiveSignatory?: CspExecutiveSignatory;
  /** §3 / §6 3PAO organization (config.yaml: auth_request.tpa.organization or --3pao-name). */
  thirdPartyAssessor?: string;
  /** §3 / §6 3PAO lead assessor (config.yaml: auth_request.tpa.lead). */
  thirdPartyAssessorLead?: ThirdPartyAssessorLead;
  /** §Addressee AO block (config.yaml: auth_request.ao_addressee). */
  aoAddressee?: AoAddressee;
  /** §2 requested action; defaults to 'initial-ato'. */
  requestedAtoType?: AtoRequestType;
  /** Impact tier — drives the §1 subject line. */
  impactLevel: 'low' | 'moderate' | 'high';
  /** §Date line ISO date (config.yaml: auth_request.submission_date); deterministic fallbacks apply. */
  submissionDate?: string;
  /** §6 CSP technical point-of-contact (config.yaml: auth_request.technical_contact). */
  technicalContact?: { name: string; title?: string; email?: string; phone?: string };
}

/**
 * Narrow view of one INDEX.json artifact row (Risk 2 — consume only the fields
 * we need; tolerate the additional fields LOOP-A.A4 emits: in_manifest, required).
 */
export interface IndexArtifact {
  filename: string;
  role: string;
  sha256: string;
  bytes: number;
  description?: string;
}

/** §4 package-contents view derived from a real out/INDEX.json (null when absent). */
export interface IndexRef {
  artifacts: IndexArtifact[];
  /** run_id recorded in INDEX.json (informational cross-check). */
  runId: string | null;
  /** SHA-256 of the INDEX.json bytes (chain-of-custody). */
  sha256: string;
}

/** §3 view derived from a real out/ap.json (null when absent). */
export interface ApMetadataRef {
  /** Organization parties recorded on the AP metadata (CSP + 3PAO). */
  organizations: string[];
  /** AP finalization date (metadata last-modified) — the assessment-plan date. */
  lastModified: string | null;
  /** AP document title. */
  title: string | null;
  /** SHA-256 of the ap.json bytes (chain-of-custody). */
  sha256: string;
}

export interface AuthCoverLetterResult {
  path: string;
  bytes: number;
  /** True when out/INDEX.json (A.A4) fed §4. */
  index_present: boolean;
  /** Artifact rows feeding §4 (0 when INDEX.json absent). */
  artifact_count: number;
  /** True when out/ap.json (A.A2) fed §3. */
  ap_present: boolean;
  /** True when a 3PAO was resolved (from operator config OR ap.json). */
  third_party_assessor_present: boolean;
  /** True when the AO addressee block was supplied. */
  ao_addressee_present: boolean;
  /** True when the CSP executive signatory was supplied. */
  executive_signatory_present: boolean;
  /** The requested authorization action (defaulted to initial-ato). */
  requested_ato_type: AtoRequestType;
  /** True when every required-for-signature operator field was supplied. */
  ready_for_signature: boolean;
  /** Missing signature-blocker list for operator action. */
  requires_operator_input: string[];
}

// ─── Readers ─────────────────────────────────────────────────────────────────

function fileSha(path: string): string | null {
  if (!existsSync(path)) return null;
  try { return createHash('sha256').update(readFileSync(path)).digest('hex'); }
  catch { return null; }
}

function readJson(path: string): any | null {
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch { return null; }
}

/**
 * Read the LOOP-A.A4 submission INDEX.json and return its artifact rows for §4.
 * Consumes only { filename, role, sha256, bytes, description } from each row and
 * ignores the additional INDEX.json fields (in_manifest, required) so a future
 * A.A4 schema addition does not break the reader (Risk 2). Returns null when the
 * file is absent or unparseable (§4 degrades to REQUIRES-OPERATOR-INPUT).
 */
export function readIndexJson(outDir: string): IndexRef | null {
  const p = resolve(outDir, 'INDEX.json');
  const doc = readJson(p);
  if (!doc || typeof doc !== 'object') return null;
  const sha = fileSha(p);
  if (!sha) return null;
  const rows = Array.isArray(doc.artifacts) ? doc.artifacts : [];
  const artifacts: IndexArtifact[] = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const filename = typeof r.filename === 'string' ? r.filename : null;
    if (!filename) continue;
    artifacts.push({
      filename,
      role: typeof r.role === 'string' ? r.role : 'unrecognized',
      sha256: typeof r.sha256 === 'string' ? r.sha256 : '',
      bytes: Number.isFinite(r.bytes) ? Number(r.bytes) : 0,
      description: typeof r.description === 'string' ? r.description : undefined,
    });
  }
  return {
    artifacts,
    runId: typeof doc.run_id === 'string' ? doc.run_id : null,
    sha256: sha,
  };
}

/**
 * Read the LOOP-A.A2 OSCAL Assessment Plan metadata for §3. The AP records
 * organization parties (CSP + 3PAO) and a finalization date (last-modified); it
 * does NOT carry a named lead assessor, so the lead comes from operator config.
 * Returns null when ap.json is absent or lacks an assessment-plan block.
 */
export function readApMetadata(outDir: string): ApMetadataRef | null {
  const p = resolve(outDir, 'ap.json');
  const doc = readJson(p);
  if (!doc || typeof doc !== 'object') return null;
  const sha = fileSha(p);
  if (!sha) return null;
  const ap = doc['assessment-plan'];
  if (!ap || typeof ap !== 'object') return null;
  const meta = ap.metadata && typeof ap.metadata === 'object' ? ap.metadata : {};
  const parties = Array.isArray(meta.parties) ? meta.parties : [];
  const organizations: string[] = [];
  for (const party of parties) {
    if (!party || typeof party !== 'object') continue;
    if (party.type && party.type !== 'organization') continue;
    if (typeof party.name === 'string' && party.name.trim() !== '') organizations.push(party.name);
  }
  return {
    organizations,
    lastModified: typeof meta['last-modified'] === 'string' ? meta['last-modified'] : null,
    title: typeof meta.title === 'string' ? meta.title : null,
    sha256: sha,
  };
}

/**
 * Resolve the assessing 3PAO organization from the operator config first, then
 * the ap.json metadata. The AP convention (core/oscal-ap.ts) records the CSP
 * organization first and the 3PAO organization second; when the operator did not
 * name the 3PAO we take the organization party that is NOT the CSP (falling back
 * to the second organization party). Returns null when neither source resolves.
 */
export function resolveThirdParty(opts: AuthCoverLetterOptions, ap: ApMetadataRef | null): string | null {
  if (opts.thirdPartyAssessor && opts.thirdPartyAssessor.trim() !== '') return opts.thirdPartyAssessor;
  if (!ap) return null;
  const orgs = ap.organizations;
  const csp = opts.cspOrganization;
  if (csp) {
    const nonCsp = orgs.find((o) => o !== csp);
    if (nonCsp) return nonCsp;
  }
  if (orgs.length >= 2) return orgs[1] ?? null;
  return null;
}

/**
 * Resolve the §Date line deterministically (Risk 4 — never a wall-clock read):
 *   1. operator submissionDate, else
 *   2. an ISO date (YYYY-MM-DD) embedded at the start of the runId, else
 *   3. a REQUIRES-OPERATOR-INPUT "dated by the operator at signing" marker.
 */
export function resolveSubmissionDate(opts: AuthCoverLetterOptions): { text: string; source: 'operator' | 'runId' | 'pending' } {
  if (opts.submissionDate && opts.submissionDate.trim() !== '') {
    return { text: opts.submissionDate.trim(), source: 'operator' };
  }
  const m = /(\d{4}-\d{2}-\d{2})/.exec(opts.runId ?? '');
  if (m) return { text: m[1]!, source: 'runId' };
  return { text: `${TBD} — dated by the operator at signing`, source: 'pending' };
}

// ─── OOXML building blocks (same pattern as rms-emit.ts) ─────────────────────

function para(text: string, style?: string): string {
  const pPr = style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : '';
  if (text === '') return `<w:p>${pPr}</w:p>`;
  const runs = text.split('\n').map((line, idx) =>
    `${idx > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
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
    const runs = text.split('\n').map((line, idx) =>
      `${idx > 0 ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlEscape(line)}</w:t>`,
    ).join('');
    return `<w:tc><w:tcPr><w:tcW w:w="${w}" w:type="dxa"/>${shadeXml}</w:tcPr>` +
      `<w:p><w:r>${runPr}${runs}</w:r></w:p></w:tc>`;
  };

  const tr = (cells: string[], bold: boolean, shade: boolean): string =>
    `<w:tr>${cells.map((cV, idx) => cell(cV, widths[idx] ?? 2000, bold, shade)).join('')}</w:tr>`;

  const body: string[] = [];
  if (headerRow) body.push(tr(headers, true, true));
  for (const r of rows) body.push(tr(r, false, false));
  return `<w:tbl>${tblPr}${grid}${body.join('')}</w:tbl>`;
}

function fieldTable(rows: Array<[string, string]>): string {
  return table(['Field', 'Value'], rows, [3000, 6000], { headerRow: false });
}

/** First 12 hex chars of a sha256 (the sha256-short shown in §4; REO — real digest). */
function shortSha(sha: string): string {
  return sha && sha.length >= 12 ? sha.slice(0, 12) : (sha || TBD);
}

/** A pretty label for the requested authorization action (§2). */
function atoTypeLabel(t: AtoRequestType): string {
  switch (t) {
    case 'continued-ato': return 'Continued Authorization to Operate (annual continuation)';
    case 'reauthorization': return 'Reauthorization (significant change / periodic reauthorization)';
    case 'initial-ato': default: return 'Initial Authorization to Operate';
  }
}

// ─── Builder (pure) ──────────────────────────────────────────────────────────

export function buildCoverLetterBodyXml(opts: AuthCoverLetterOptions): {
  xml: string;
  stats: Omit<AuthCoverLetterResult, 'path' | 'bytes'>;
} {
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const csp = opts.cspOrganization || TBD;
  const atoType: AtoRequestType = opts.requestedAtoType ?? 'initial-ato';
  const docUuid = deterministicUuid(`auth-cover-letter:${systemId}:${opts.runId}`);

  // Real LOOP-A corpus.
  const index = readIndexJson(opts.outDir);
  const ap = readApMetadata(opts.outDir);
  const thirdParty = resolveThirdParty(opts, ap);
  const date = resolveSubmissionDate(opts);

  // Required-for-signature tracking (test #11: signatory + addressee + tpa + atoType).
  const missing: string[] = [];
  if (!opts.cspExecutiveSignatory) missing.push('cspExecutiveSignatory (config.yaml: auth_request.executive_signatory)');
  if (!opts.aoAddressee) missing.push('aoAddressee (config.yaml: auth_request.ao_addressee)');
  if (!thirdParty) missing.push('thirdPartyAssessor (config.yaml: auth_request.tpa or out/ap.json)');
  // atoType always resolves (default initial-ato) — no blocker.

  const parts: string[] = [];

  // ── Title block ──
  parts.push(para('FedRAMP Authorization Request — Transmittal Cover Letter', 'Title'));
  parts.push(para(`${systemName} — FedRAMP ${opts.impactLevel.toUpperCase()} Authorization Package (PM-10)`, 'Subtitle'));
  parts.push(para(
    'DRAFT — auto-generated by fedramp-20x-cloud-evidence. The §4 Package Contents table is derived ' +
    'from the run\'s real submission INDEX.json (LOOP-A.A4) and the §3 3PAO Statement from the run\'s ' +
    `real Assessment Plan (out/ap.json, LOOP-A.A2) when present. The operator must complete every ${TBD} ` +
    'marker — and the CSP executive signatory must sign §7 — before this letter is transmitted. This is ' +
    'the CSP-side cover letter that ACCOMPANIES the package; it is not the Authorizing Official\'s ATO ' +
    'letter (the AO\'s response).',
    'Disclaimer',
  ));

  // ── Letterhead ──
  parts.push(heading('Letterhead', 2));
  parts.push(fieldTable([
    ['From (CSP Organization)', csp],
    ['CSP Mailing Address', opts.cspAddress && opts.cspAddress.trim() !== '' ? opts.cspAddress : `${TBD} (config.yaml: org.address)`],
    ['Date', date.text],
    ['Document UUID', docUuid],
  ]));
  if (date.source !== 'operator') {
    parts.push(para(
      date.source === 'runId'
        ? `Note: the date above was derived from the run identifier (${opts.runId}) for determinism; set config.yaml: auth_request.submission_date to override with the true transmittal date.`
        : 'Note: no submission date was supplied; the operator dates the letter at signing. Set config.yaml: auth_request.submission_date for a deterministic date (Risk 4).',
      'Disclaimer',
    ));
  }

  // ── Addressee ──
  parts.push(heading('Addressee', 2));
  if (opts.aoAddressee) {
    const a = opts.aoAddressee;
    const rows: Array<[string, string]> = [
      ['To (Authorizing Official)', a.name || TBD],
      ['Title', a.title || TBD],
      ['Agency', a.agency || TBD],
      ['Address', a.address || TBD],
    ];
    if (a.designee && a.designee.trim() !== '') rows.push(['Delegated AO Designee', a.designee]);
    parts.push(fieldTable(rows));
  } else {
    parts.push(para(
      `${TBD}: the Authorizing Official addressee was not supplied. Set config.yaml: auth_request.ao_addressee ` +
      '(name / title / agency / address; optional designee for a delegated authorizing-official designate, Risk 5). ' +
      'The FedRAMP PMO is cc\'d via §6 Primary Contacts when the package is transmitted through the PMO track.',
    ));
  }

  // ── §1 Subject ──
  parts.push(heading('1. Subject', 1));
  parts.push(para(
    `Subject: FedRAMP ${opts.impactLevel.toUpperCase()} Authorization Request — ${systemName}.`,
  ));
  parts.push(para(
    'This letter transmits the FedRAMP authorization package for the system identified below and formally ' +
    'requests an authorization decision. It supports the NIST SP 800-53 Rev. 5 PM-10 (Authorization Process) ' +
    `requirement to "${PM_10_QUOTE}" and the NIST SP 800-37 Rev. 2 §3.6 (Authorize) RMF step under which the ` +
    'Authorizing Official reviews the package and renders an authorization decision.',
  ));

  // ── §2 Request Summary ──
  parts.push(heading('2. Request Summary', 1));
  parts.push(para(
    `${csp} respectfully submits the attached FedRAMP authorization package for ${systemName} and requests ` +
    `the following authorization action: ${atoTypeLabel(atoType)}.` +
    (atoType === 'reauthorization'
      ? ' This reauthorization request reflects a significant change to (or the periodic reauthorization of) a ' +
        'previously authorized system; the package documents the change and its security impact.'
      : atoType === 'continued-ato'
        ? ' This continued-authorization request reflects the annual continuation of an existing authorization ' +
          'supported by the continuous-monitoring evidence enclosed.'
        : ' This is an initial authorization request for a system not previously authorized at this impact level.'),
  ));
  parts.push(fieldTable([
    ['System Name', systemName],
    ['System ID', systemId],
    ['CSP Organization', csp],
    ['FedRAMP Impact Level', opts.impactLevel.toUpperCase()],
    ['Requested Action', atoTypeLabel(atoType)],
    ['Run ID', opts.runId],
    ['FRMR Catalog Version', opts.frmrVersion],
  ]));

  // ── §3 3PAO Statement ──
  parts.push(heading('3. Independent Assessment (3PAO) Statement', 1));
  if (thirdParty) {
    const apDate = ap?.lastModified ?? null;
    const lead = opts.thirdPartyAssessorLead;
    parts.push(para(
      `The security assessment supporting this authorization request was performed by ${thirdParty}, an ` +
      'accredited FedRAMP Third Party Assessment Organization (3PAO). The 3PAO independently tested the ' +
      'security controls per the enclosed Assessment Plan and documented the results in the enclosed ' +
      'Assessment Results (SAR).',
    ));
    parts.push(fieldTable([
      ['Assessing 3PAO', thirdParty],
      ['3PAO Lead Assessor', lead?.name ? `${lead.name}${lead.title ? `, ${lead.title}` : ''}${lead.email ? ` <${lead.email}>` : ''}` : `${TBD} (config.yaml: auth_request.tpa.lead)`],
      ['Assessment Plan Reference', ap ? `out/ap.json${apDate ? ` (finalized ${apDate})` : ''}` : `${TBD} — Assessment Plan (out/ap.json) not present this run; run with --oscal-ap to anchor this reference`],
      ['3PAO Source', opts.thirdPartyAssessor ? 'operator-supplied (config.yaml: auth_request.tpa / --3pao-name)' : 'out/ap.json metadata party'],
    ]));
  } else {
    parts.push(para(
      `${TBD}: the assessing 3PAO was not identified. Supply it via config.yaml: auth_request.tpa.organization ` +
      '(or the --3pao-name flag), or run with --oscal-ap so the Assessment Plan (out/ap.json) records the 3PAO ' +
      'organization party (Risk 3). A FedRAMP authorization package requires an independent 3PAO assessment.',
    ));
  }

  // ── §4 Package Contents ──
  parts.push(heading('4. Package Contents', 1));
  parts.push(para(
    'The following artifacts are enclosed in this submission package. The list is auto-enumerated from the ' +
    'signed submission INDEX.json (LOOP-A.A4) with the real per-artifact SHA-256 (first 12 hex chars) and ' +
    'byte size. Per the FedRAMP Initial Authorization Package Checklist, each required artifact is present ' +
    'or its absence is noted in the INDEX.json gaps list.',
  ));
  if (index && index.artifacts.length > 0) {
    const sorted = [...index.artifacts].sort((a, b) => a.filename.localeCompare(b.filename)); // Q2: alphabetical for stable diffing
    parts.push(table(
      ['Artifact', 'Role', 'SHA-256 (short)', 'Bytes'],
      sorted.map((a) => [a.filename, a.role, shortSha(a.sha256), String(a.bytes)]),
      [3200, 3000, 1900, 1200],
    ));
    parts.push(para(
      `Total artifacts enclosed: ${index.artifacts.length}. The full submission INDEX.json (SHA-256 ` +
      `${index.sha256}) is itself enclosed and carries the complete per-artifact manifest, the OSCAL chain ` +
      'check, and the required-artifact gap list. The package tarball\'s own SHA-256 is provided in the ' +
      'post-bundle companion summary, since this cover letter is enclosed inside the tarball (Q1).',
    ));
  } else {
    parts.push(para(
      `${TBD}: the submission INDEX.json (out/INDEX.json, LOOP-A.A4) was not present when this letter was ` +
      'generated, so the package-contents table could not be auto-enumerated. Run with --submission-bundle ' +
      'so the INDEX.json is built before the cover letter is emitted (the orchestrator sequences ' +
      'INDEX-build → cover-letter → bundle-pack). Until then, enumerate the package contents manually per the ' +
      'FedRAMP Initial Authorization Package Checklist.',
    ));
  }

  // ── §5 Requested Action ──
  parts.push(heading('5. Requested Action', 1));
  parts.push(para(
    `${csp} respectfully requests that the Authorizing Official review the enclosed package and render an ` +
    'authorization decision within the applicable FedRAMP review timeline (see the FedRAMP Agency ' +
    'Authorization Playbook for current review-cadence guidance). Upon a favorable decision we request ' +
    'issuance of an Authorization to Operate (ATO) letter in the form of the FedRAMP ATO Letter Template. ' +
    'This cover letter makes no representation or commitment on behalf of the Authorizing Official; the ' +
    'authorization decision rests solely with the AO.',
  ));

  // ── §6 Primary Contacts ──
  parts.push(heading('6. Primary Contacts', 1));
  const sig = opts.cspExecutiveSignatory;
  const tech = opts.technicalContact;
  const lead2 = opts.thirdPartyAssessorLead;
  parts.push(table(
    ['Role', 'Name', 'Contact'],
    [
      ['CSP Executive Signatory', sig?.name || TBD, sig ? `${sig.title}${sig.email ? ` — ${sig.email}` : ''}${sig.phone ? ` — ${sig.phone}` : ''}` : `${TBD} (config.yaml: auth_request.executive_signatory)`],
      ['CSP Technical Lead', tech?.name || `${TBD}`, tech ? `${tech.title ?? ''}${tech.email ? ` — ${tech.email}` : ''}${tech.phone ? ` — ${tech.phone}` : ''}`.trim() || TBD : `${TBD} (config.yaml: auth_request.technical_contact)`],
      ['Assessing 3PAO', thirdParty || TBD, lead2?.name ? `${lead2.name}${lead2.email ? ` — ${lead2.email}` : ''}` : `${TBD} (config.yaml: auth_request.tpa.lead)`],
    ],
    [3000, 3000, 3300],
  ));
  parts.push(para(
    'When the package is transmitted through the FedRAMP PMO track, the FedRAMP PMO is copied on this ' +
    'transmittal in addition to the Authorizing Official named in the Addressee block above.',
  ));

  // ── §7 Closing + Signature ──
  parts.push(heading('7. Closing and Signature', 1));
  parts.push(para(
    'We appreciate your review of this authorization request and stand ready to support the assessment and ' +
    'authorization process. Respectfully submitted,',
  ));
  if (sig) {
    parts.push(para(''));
    parts.push(para('_______________________________________'));
    parts.push(para(`${sig.name}`));
    parts.push(para(`${sig.title}, ${csp}`));
    parts.push(para(`${sig.email}${sig.phone ? ` — ${sig.phone}` : ''}`));
    parts.push(para(`Date: ${date.source === 'operator' ? date.text : '____________________'}`));
  } else {
    parts.push(para(
      `${TBD}: the CSP executive signatory was not supplied, so the signature block is left unfilled. Set ` +
      'config.yaml: auth_request.executive_signatory (name / title / email / phone). The .docx is digitally ' +
      'signed by the pipeline (Ed25519 over the submission-bundle INDEX.json); this signature block is the ' +
      'separate wet/electronic executive signature and is never auto-signed by the toolkit (Risk 6).',
    ));
  }

  // ── Provenance footer ──
  parts.push(heading('Provenance', 2));
  parts.push(para(
    `Generated by core/auth-cover-letter-emit.ts (run ${opts.runId}, FRMR ${opts.frmrVersion}). ` +
    `§4 package contents: ${index ? `INDEX.json (sha256 ${index.sha256}, ${index.artifacts.length} artifact(s))` : 'INDEX.json not present this run'}. ` +
    `§3 3PAO statement: ${ap ? `ap.json (sha256 ${ap.sha256})` : 'ap.json not present this run'}. ` +
    `Requested action: ${atoTypeLabel(atoType)}. ` +
    `Control basis: NIST SP 800-53 Rev. 5 PM-10 — ${SP_800_53_URL}. RMF authorize step: NIST SP 800-37 Rev. 2 — ${SP_800_37_URL}. ` +
    `Request structure: FedRAMP Agency Authorization Playbook — ${PLAYBOOK_URL}. Package contents basis: FedRAMP Initial Authorization Package Checklist — ${CHECKLIST_URL}. ` +
    `Counterpart ATO letter: FedRAMP ATO Letter Template — ${ATO_TEMPLATE_URL}. ` +
    'This document is deterministic (no wall-clock time); its integrity is anchored by the signed ' +
    'submission-bundle INDEX.json (SHA-256 + Ed25519).',
  ));

  // ── Page geometry (US Letter) ──
  const sectPr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>' +
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>';

  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:w="${W_NS}"><w:body>${parts.join('')}${sectPr}</w:body></w:document>`;

  return {
    xml,
    stats: {
      index_present: index !== null,
      artifact_count: index?.artifacts.length ?? 0,
      ap_present: ap !== null,
      third_party_assessor_present: thirdParty !== null,
      ao_addressee_present: opts.aoAddressee !== undefined,
      executive_signatory_present: opts.cspExecutiveSignatory !== undefined,
      requested_ato_type: atoType,
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

function coreXml(systemName: string, docUuid: string): string {
  const title = `FedRAMP Authorization Request Cover Letter — ${systemName} [${docUuid}]`;
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

/** Pure: render the authorization-request cover letter Word document to a Buffer. */
export function renderAuthCoverLetterDocx(opts: AuthCoverLetterOptions): {
  buffer: Buffer;
  stats: Omit<AuthCoverLetterResult, 'path' | 'bytes'>;
} {
  const { xml, stats } = buildCoverLetterBodyXml(opts);
  const systemName = opts.systemName || TBD;
  const systemId = opts.systemId || TBD;
  const docUuid = deterministicUuid(`auth-cover-letter:${systemId}:${opts.runId}`);
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

/** Read INDEX.json + ap.json, render, and write auth-request-cover-letter.docx. */
export function emitAuthCoverLetterDocx(opts: AuthCoverLetterOptions): AuthCoverLetterResult {
  const { buffer, stats } = renderAuthCoverLetterDocx(opts);
  const outPath = opts.outPath ?? resolve(opts.outDir, 'auth-request-cover-letter.docx');
  writeFileSync(outPath, buffer);
  log.info({
    event: 'auth_cover_letter.emitted',
    path: outPath,
    bytes: buffer.length,
    index_present: stats.index_present,
    artifact_count: stats.artifact_count,
    ap_present: stats.ap_present,
    third_party_assessor_present: stats.third_party_assessor_present,
    ao_addressee_present: stats.ao_addressee_present,
    executive_signatory_present: stats.executive_signatory_present,
    requested_ato_type: stats.requested_ato_type,
    ready_for_signature: stats.ready_for_signature,
    requires_operator_input_count: stats.requires_operator_input.length,
  });
  return { path: outPath, bytes: buffer.length, ...stats };
}
