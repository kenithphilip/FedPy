/**
 * Per-source parsers for the prohibited-vendor catalog (LOOP-W.W1).
 *
 * This is the leaf module of the W.W1 ingester: it converts each authoritative
 * federal source's raw bytes/objects into normalized `ProhibitedVendorEntity[]`.
 * It performs NO network I/O and NO disk writes — callers hand it already-read
 * bytes (from a snapshot directory or test fixture) and it returns structured
 * entities. `core/prohibited-vendors-catalog.ts` composes these parsers into the
 * signed canonical-JSON catalog.
 *
 * Sources covered (see docs/slices/W/W.W1.md §2 for verbatim authority quotes):
 *   - OFAC SDN (Treasury)                — SDN.CSV + ADD.CSV + ALT.CSV
 *   - BIS Entity List (Commerce)         — trade.gov consolidated screening list CSV
 *   - SAM.gov Exclusions (GSA)           — Entity Management API v3 JSON pages
 *   - FAR 52.204-25 named entities       — committed statutory constant JSON
 *   - NDAA FY2019 §889 named entities    — committed statutory constant JSON
 *   - NDAA FY2018 §1634 Kaspersky        — committed statutory constant JSON
 *   - FASCSA covered-article orders      — operator-maintained register JSON
 *
 * REO compliance: every string literal a parser emits comes from the source
 * bytes it was handed or from a statute citation. A row that cannot be
 * normalized is NOT dropped — it is emitted with a `requires_operator_input`
 * marker so the gap is visible (REO Rule 1.5: no silent fallback that masks
 * missing data).
 */

// ─── Source identifiers + entity shape (the catalog substrate types) ─────────

export type ProhibitedVendorsSourceId =
  | 'ofac-sdn'
  | 'bis-entity-list'
  | 'sam-exclusions'
  | 'far-52-204-25'
  | 'ndaa-889'
  | 'ndaa-1634'
  | 'fascsa';

export type ProhibitedVendorEntityType =
  | 'individual'
  | 'organization'
  | 'vessel'
  | 'aircraft'
  | 'unknown';

export interface ProhibitedVendorEntity {
  source_id: ProhibitedVendorsSourceId;
  /** Source-native record key: OFAC ent_num, SAM ueiSAM, FAR entity slug, etc. */
  source_record_id: string;
  /** NFKC-normalized, uppercase, whitespace-collapsed. */
  name_canonical: string;
  /** Same as name_canonical but with common corporate suffixes stripped (for downstream matching). */
  name_canonical_stripped: string;
  /** Exactly as it appears in the source. */
  name_verbatim: string;
  /** Sorted, deduplicated alternate names. */
  aliases: string[];
  entity_type: ProhibitedVendorEntityType;
  addresses: Array<{ verbatim: string; country?: string }>;
  /** OFAC programs / FASC order ids / EAR license requirements / statute paragraphs. */
  programs: string[];
  /** Source-specific authority pin, e.g. "Pub. L. 115-91 §1634". */
  authority_citation: string;
  /** SAM cross-reference, OFAC alt id, FASC cross-reference, etc. */
  cross_reference?: string;
  /** ISO-8601 if known. */
  effective_date?: string;
  /** ISO-8601 if known. */
  termination_date?: string;
  /** Forensic recovery pointer back into the snapshot. */
  raw_record_pointer: {
    snapshot_filename: string;
    line_number?: number;
    page_number?: number;
    sheet_name?: string;
  };
  /** Set when normalization failed; the row is kept, not dropped. */
  requires_operator_input?: string;
}

/**
 * Thrown when a source's observed schema diverges from what the parser expects
 * (a renamed CSV column, a missing JSON key). Carries an actionable remediation
 * message rather than emitting a silently-wrong catalog (W.W1 §9 R1).
 */
export class SourceSchemaDriftError extends Error {
  readonly source: ProhibitedVendorsSourceId;
  constructor(source: ProhibitedVendorsSourceId, message: string) {
    super(`[${source}] schema drift: ${message}`);
    this.name = 'SourceSchemaDriftError';
    this.source = source;
  }
}

// ─── Name normalization ──────────────────────────────────────────────────────

/** NFKC normalize → uppercase → collapse internal whitespace runs → trim. */
export function normalizeName(raw: string): string {
  return raw
    .normalize('NFKC')
    .toUpperCase()
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Corporate-suffix tokens stripped for the `name_canonical_stripped` field.
 * Downstream matching (W.W2/W.W3) may use either the full or stripped form;
 * stripping raises recall at the cost of precision (documented in W.W3 risks).
 * These are universal legal-form abbreviations, not source data.
 */
const CORPORATE_SUFFIXES = [
  'LLC', 'L.L.C.', 'INC', 'INC.', 'INCORPORATED', 'CORP', 'CORP.', 'CORPORATION',
  'CO', 'CO.', 'COMPANY', 'LTD', 'LTD.', 'LIMITED', 'PLC', 'GMBH', 'AG', 'SA',
  'S.A.', 'NV', 'N.V.', 'BV', 'B.V.', 'PTE', 'PTY', 'LLP', 'LP', 'AB', 'OY',
  'KK', 'K.K.', 'SRL', 'SPA', 'S.P.A.',
];

/** normalizeName, then drop trailing/embedded corporate-form suffix tokens. */
export function normalizeNameStripped(raw: string): string {
  const base = normalizeName(raw);
  // Split on spaces/commas, drop suffix tokens, re-join. Punctuation-only
  // tokens left by suffix removal are also dropped.
  const suffixSet = new Set(CORPORATE_SUFFIXES.map((s) => s.toUpperCase()));
  const tokens = base
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter(Boolean)
    .filter((t) => !suffixSet.has(t.replace(/[.,]+$/, '')) && !suffixSet.has(t));
  return tokens.join(' ').replace(/\s+/g, ' ').trim();
}

// ─── RFC-4180 CSV parser ─────────────────────────────────────────────────────

/**
 * Parse CSV text into rows of string cells. Handles quoted fields, embedded
 * commas, embedded newlines, and doubled quotes ("" → "). The OFAC and
 * trade.gov feeds are quoted CSV; a naive split would corrupt addresses that
 * contain commas.
 */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let field = '';
  let row: string[] = [];
  let inQuotes = false;
  // Strip a UTF-8 BOM if present.
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    if (inQuotes) {
      if (c === '"') {
        if (src[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      row.push(field); field = '';
    } else if (c === '\n') {
      row.push(field); field = '';
      rows.push(row); row = [];
    } else if (c === '\r') {
      // swallow; the following \n (if any) closes the row
    } else {
      field += c;
    }
  }
  // Flush the final field/row if the file didn't end with a newline.
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** OFAC uses "-0-" as a null sentinel across all its delimited feeds. */
function ofacVal(s: string | undefined): string {
  const v = (s ?? '').trim();
  return v === '-0-' ? '' : v;
}

// ─── OFAC SDN parser ─────────────────────────────────────────────────────────

/**
 * Columns of the OFAC SDN.CSV / ADD.CSV / ALT.CSV delimited feeds, per the
 * `Data_Specification.pdf` published alongside the feeds. These are headerless
 * fixed-position CSV files keyed by `ent_num`.
 */
const OFAC_SDN_COLS = 12;   // ent_num,SDN_Name,SDN_Type,Program,Title,Call_Sign,Vess_type,Tonnage,GRT,Vess_flag,Vess_owner,Remarks
const OFAC_ALT_COLS = 5;    // ent_num,alt_num,alt_type,alt_name,alt_remarks
const OFAC_ADD_COLS = 6;    // ent_num,add_num,address,city_state_province_postal,country,add_remarks

function ofacEntityType(sdnType: string): ProhibitedVendorEntityType {
  const t = sdnType.trim().toLowerCase();
  if (t === 'individual') return 'individual';
  if (t === 'vessel') return 'vessel';
  if (t === 'aircraft') return 'aircraft';
  if (t === 'entity' || t === '') return 'organization';
  return 'unknown';
}

/**
 * Parse the OFAC SDN feeds into entities. `sdnCsv` is required; `addCsv` and
 * `altCsv` are optional joins on `ent_num` for addresses and aliases.
 */
export function parseOfacSdn(
  sdnCsv: string,
  addCsv?: string,
  altCsv?: string,
  snapshotFilename = 'sdn.csv',
): ProhibitedVendorEntity[] {
  const sdnRows = parseCsv(sdnCsv).filter((r) => r.length > 1 || (r.length === 1 && r[0]!.trim() !== ''));
  if (sdnRows.length > 0) {
    const widths = sdnRows.map((r) => r.length);
    const maxWidth = Math.max(...widths);
    if (maxWidth < OFAC_SDN_COLS - 1) {
      throw new SourceSchemaDriftError(
        'ofac-sdn',
        `SDN.CSV expected ~${OFAC_SDN_COLS} columns (ent_num,SDN_Name,SDN_Type,Program,...); widest row has ${maxWidth}. Update parseOfacSdn in core/prohibited-vendors-parsers.ts.`,
      );
    }
  }

  // Join aliases from ALT on ent_num.
  const aliasesByEnt = new Map<string, string[]>();
  if (altCsv) {
    for (const r of parseCsv(altCsv)) {
      if (r.length < OFAC_ALT_COLS) continue;
      const ent = ofacVal(r[0]);
      const altName = ofacVal(r[3]);
      if (!ent || !altName) continue;
      const list = aliasesByEnt.get(ent) ?? [];
      list.push(altName);
      aliasesByEnt.set(ent, list);
    }
  }

  // Join addresses from ADD on ent_num.
  const addrsByEnt = new Map<string, Array<{ verbatim: string; country?: string }>>();
  if (addCsv) {
    for (const r of parseCsv(addCsv)) {
      if (r.length < OFAC_ADD_COLS) continue;
      const ent = ofacVal(r[0]);
      const street = ofacVal(r[2]);
      const cityLine = ofacVal(r[3]);
      const country = ofacVal(r[4]);
      const verbatim = [street, cityLine, country].filter(Boolean).join(', ');
      if (!ent || !verbatim) continue;
      const list = addrsByEnt.get(ent) ?? [];
      list.push(country ? { verbatim, country } : { verbatim });
      addrsByEnt.set(ent, list);
    }
  }

  const out: ProhibitedVendorEntity[] = [];
  for (let i = 0; i < sdnRows.length; i++) {
    const r = sdnRows[i]!;
    const ent = ofacVal(r[0]);
    const nameVerbatim = ofacVal(r[1]);
    const sdnType = ofacVal(r[2]);
    const program = ofacVal(r[3]);
    const remarks = ofacVal(r[11]);
    if (!ent) continue; // a blank trailing line, not a record

    const aliases = Array.from(new Set((aliasesByEnt.get(ent) ?? []).map((a) => normalizeName(a)).filter(Boolean))).sort();
    const programs = program ? program.split(/\s*;\s*/).map((p) => p.trim()).filter(Boolean) : [];

    const entity: ProhibitedVendorEntity = {
      source_id: 'ofac-sdn',
      source_record_id: ent,
      name_canonical: nameVerbatim ? normalizeName(nameVerbatim) : '',
      name_canonical_stripped: nameVerbatim ? normalizeNameStripped(nameVerbatim) : '',
      name_verbatim: nameVerbatim,
      aliases,
      entity_type: ofacEntityType(sdnType),
      addresses: addrsByEnt.get(ent) ?? [],
      programs,
      authority_citation: 'OFAC SDN (IEEPA, 50 U.S.C. §§1701-1707; TWEA, 50 U.S.C. App. §§1-44)',
      cross_reference: remarks || undefined,
      raw_record_pointer: { snapshot_filename: snapshotFilename, line_number: i + 1 },
    };
    if (!nameVerbatim) entity.requires_operator_input = 'missing-name-canonical';
    out.push(entity);
  }
  return out;
}

// ─── BIS Entity List parser (via trade.gov consolidated screening list) ──────

const BIS_ENTITY_LIST_SOURCE = 'Entity List (EL) - Bureau of Industry and Security';

/**
 * Parse the trade.gov consolidated screening list CSV, filtering to only the
 * BIS Entity List rows. The consolidated CSV has a header row; we key off the
 * `source`, `name`, `entity_number`, `alt_names`, `addresses`, `programs`,
 * and `type` columns.
 */
export function parseBisEntityList(
  consolidatedCsv: string,
  snapshotFilename = 'consolidated.csv',
): ProhibitedVendorEntity[] {
  const rows = parseCsv(consolidatedCsv).filter((r) => r.some((c) => c.trim() !== ''));
  if (rows.length === 0) return [];
  const header = rows[0]!.map((h) => h.trim().toLowerCase());
  const col = (name: string) => header.indexOf(name);
  const iSource = col('source');
  const iName = col('name');
  const iId = col('entity_number') >= 0 ? col('entity_number') : col('_id');
  if (iSource < 0 || iName < 0) {
    throw new SourceSchemaDriftError(
      'bis-entity-list',
      `consolidated.csv missing required columns (have: ${header.join(', ')}). Expected at least 'source' and 'name'. Update parseBisEntityList in core/prohibited-vendors-parsers.ts.`,
    );
  }
  const iAlt = col('alt_names');
  const iAddr = col('addresses');
  const iPrograms = col('programs');
  const iType = col('type');

  const out: ProhibitedVendorEntity[] = [];
  for (let i = 1; i < rows.length; i++) {
    const r = rows[i]!;
    const src = (r[iSource] ?? '').trim();
    if (src !== BIS_ENTITY_LIST_SOURCE) continue;
    const nameVerbatim = (r[iName] ?? '').trim();
    const recId = (iId >= 0 ? (r[iId] ?? '').trim() : '') || `${normalizeNameStripped(nameVerbatim)}#${i}`;
    const aliases = iAlt >= 0
      ? Array.from(new Set((r[iAlt] ?? '').split(/\s*;\s*/).map((a) => normalizeName(a)).filter(Boolean))).sort()
      : [];
    const addresses = iAddr >= 0 && (r[iAddr] ?? '').trim()
      ? [{ verbatim: (r[iAddr] ?? '').trim() }]
      : [];
    const programs = iPrograms >= 0
      ? (r[iPrograms] ?? '').split(/\s*;\s*/).map((p) => p.trim()).filter(Boolean)
      : [];
    const typeRaw = (iType >= 0 ? (r[iType] ?? '') : '').trim().toLowerCase();
    const entity_type: ProhibitedVendorEntityType =
      typeRaw === 'individual' ? 'individual' : typeRaw ? 'organization' : 'organization';

    const entity: ProhibitedVendorEntity = {
      source_id: 'bis-entity-list',
      source_record_id: recId,
      name_canonical: nameVerbatim ? normalizeName(nameVerbatim) : '',
      name_canonical_stripped: nameVerbatim ? normalizeNameStripped(nameVerbatim) : '',
      name_verbatim: nameVerbatim,
      aliases,
      entity_type,
      addresses,
      programs: programs.length ? programs : ['EAR Entity List (15 CFR 744 Supp. No. 4)'],
      authority_citation: '15 CFR Part 744, Supplement No. 4 (EAR Entity List); 15 CFR §744.16',
      raw_record_pointer: { snapshot_filename: snapshotFilename, line_number: i + 1 },
    };
    if (!nameVerbatim) entity.requires_operator_input = 'missing-name-canonical';
    out.push(entity);
  }
  return out;
}

// ─── SAM.gov Exclusions parser ───────────────────────────────────────────────

interface SamExclusionRecord {
  ueiSAM?: string;
  legalBusinessName?: string;
  exclusionName?: string;
  exclusionTypeDesc?: string;
  exclusionProgramDesc?: string;
  excludingAgencyName?: string;
  activeDate?: string;
  terminationDate?: string;
  crossReference?: string;
  additionalComments?: string;
  classificationType?: string;
}

/** Pull the exclusion records out of one SAM API v3 page, tolerating shape variance. */
function extractSamRecords(page: unknown): SamExclusionRecord[] {
  if (!page || typeof page !== 'object') return [];
  const obj = page as Record<string, unknown>;
  // v3 returns { totalRecords, entityData: [ { ... exclusion fields ... } ] }.
  // Some bulk extracts wrap the list under `excludedEntities` or are a bare array.
  const candidates =
    (Array.isArray(obj.entityData) && obj.entityData) ||
    (Array.isArray(obj.excludedEntities) && obj.excludedEntities) ||
    (Array.isArray(obj.exclusionDetails) && obj.exclusionDetails) ||
    (Array.isArray(page) ? (page as unknown[]) : null);
  if (!candidates) return [];
  return (candidates as unknown[]).map((rec) => {
    const r = (rec ?? {}) as Record<string, any>;
    // Flatten the common nested shapes (entityRegistration / exclusionDetails).
    const reg = (r.entityRegistration ?? {}) as Record<string, any>;
    const det = (r.exclusionDetails ?? r.exclusion ?? {}) as Record<string, any>;
    return {
      ueiSAM: r.ueiSAM ?? reg.ueiSAM ?? r.uei,
      legalBusinessName: r.legalBusinessName ?? reg.legalBusinessName ?? r.exclusionName,
      exclusionName: r.exclusionName ?? det.exclusionName,
      exclusionTypeDesc: r.exclusionTypeDesc ?? det.exclusionType,
      exclusionProgramDesc: r.exclusionProgramDesc ?? det.exclusionProgram,
      excludingAgencyName: r.excludingAgencyName ?? det.excludingAgencyName,
      activeDate: r.activeDate ?? det.activeDate,
      terminationDate: r.terminationDate ?? det.terminationDate,
      crossReference: r.crossReference ?? det.crossReferenceName,
      additionalComments: r.additionalComments ?? det.additionalComments,
      classificationType: r.classificationType ?? det.classificationType,
    } as SamExclusionRecord;
  });
}

/** Flatten a list of SAM API v3 exclusion pages into entities. */
export function parseSamExclusions(
  pages: unknown[],
  snapshotFilenamePrefix = 'sam-exclusions-page',
): ProhibitedVendorEntity[] {
  const out: ProhibitedVendorEntity[] = [];
  for (let p = 0; p < pages.length; p++) {
    const records = extractSamRecords(pages[p]);
    for (let i = 0; i < records.length; i++) {
      const rec = records[i]!;
      const nameVerbatim = (rec.legalBusinessName ?? rec.exclusionName ?? '').trim();
      const uei = (rec.ueiSAM ?? '').trim();
      const recId = uei || `${normalizeNameStripped(nameVerbatim)}#${p + 1}-${i + 1}`;
      const programs = [rec.exclusionTypeDesc, rec.exclusionProgramDesc, rec.excludingAgencyName]
        .map((s) => (s ?? '').trim())
        .filter(Boolean);
      const entity: ProhibitedVendorEntity = {
        source_id: 'sam-exclusions',
        source_record_id: recId,
        name_canonical: nameVerbatim ? normalizeName(nameVerbatim) : '',
        name_canonical_stripped: nameVerbatim ? normalizeNameStripped(nameVerbatim) : '',
        name_verbatim: nameVerbatim,
        aliases: [],
        entity_type: (rec.classificationType ?? '').toLowerCase().includes('individual') ? 'individual' : 'organization',
        addresses: [],
        programs: programs.length ? programs : ['SAM Exclusion (FAR 9.404)'],
        authority_citation: 'FAR Subpart 9.4 (Debarment, Suspension, and Ineligibility); 48 CFR §9.404',
        cross_reference: (rec.crossReference ?? '').trim() || undefined,
        effective_date: (rec.activeDate ?? '').trim() || undefined,
        termination_date: (rec.terminationDate ?? '').trim() || undefined,
        raw_record_pointer: {
          snapshot_filename: `${snapshotFilenamePrefix}-${String(p + 1).padStart(3, '0')}.json`,
          line_number: i + 1,
        },
      };
      if (!nameVerbatim) entity.requires_operator_input = 'missing-name-canonical';
      out.push(entity);
    }
  }
  return out;
}

// ─── Statutory-constant parsers (FAR 52.204-25, NDAA §889, NDAA §1634) ───────

interface FarNamedEntitiesFile {
  authority_citation?: string;
  entities?: Array<{ slug?: string; name_verbatim?: string; statute_paragraph?: string; category?: string; note?: string }>;
  catch_all?: { slug?: string; name_verbatim?: string; statute_paragraph?: string; category?: string; note?: string };
}

function farEntity(
  source: 'far-52-204-25' | 'ndaa-889',
  e: { slug?: string; name_verbatim?: string; statute_paragraph?: string; note?: string },
  authority: string,
  snapshotFilename: string,
): ProhibitedVendorEntity {
  const nameVerbatim = (e.name_verbatim ?? '').trim();
  return {
    source_id: source,
    source_record_id: (e.slug ?? normalizeNameStripped(nameVerbatim)).trim(),
    name_canonical: normalizeName(nameVerbatim),
    name_canonical_stripped: normalizeNameStripped(nameVerbatim),
    name_verbatim: nameVerbatim,
    aliases: [],
    entity_type: 'organization',
    addresses: [],
    programs: [e.statute_paragraph ?? authority, e.note ?? ''].filter(Boolean) as string[],
    authority_citation: e.statute_paragraph ? `${authority} (${e.statute_paragraph})` : authority,
    raw_record_pointer: { snapshot_filename: snapshotFilename },
  };
}

/** FAR 52.204-25(a): the 5 named entities + the §889(f)(3)(D) catch-all (6 total). */
export function parseFar52204_25(
  file: FarNamedEntitiesFile,
  snapshotFilename = 'far-52-204-25-named-entities.json',
): ProhibitedVendorEntity[] {
  const authority = file.authority_citation ?? 'FAR 52.204-25(a)';
  const out: ProhibitedVendorEntity[] = [];
  for (const e of file.entities ?? []) {
    out.push(farEntity('far-52-204-25', e, authority, snapshotFilename));
  }
  if (file.catch_all) {
    out.push(farEntity('far-52-204-25', file.catch_all, authority, snapshotFilename));
  }
  return out;
}

/** NDAA FY2019 §889 covered telecommunications entities (the 5 named; no catch-all). */
export function parseNdaa889(
  file: FarNamedEntitiesFile,
  snapshotFilename = 'far-52-204-25-named-entities.json',
): ProhibitedVendorEntity[] {
  const authority = 'Pub. L. 115-232 §889(f)(3)';
  return (file.entities ?? []).map((e) => farEntity('ndaa-889', e, authority, snapshotFilename));
}

interface NdaaKasperskyFile {
  authority_citation?: string;
  prohibition_effective_date?: string;
  entities?: Array<{ slug?: string; name_verbatim?: string; covered_entity_class?: string; statute_paragraph?: string; note?: string }>;
}

/** NDAA FY2018 §1634: the 4 Kaspersky-Lab covered-entity classes. */
export function parseNdaa1634(
  file: NdaaKasperskyFile,
  snapshotFilename = 'ndaa-1634-named-entities.json',
): ProhibitedVendorEntity[] {
  const authority = file.authority_citation ?? 'Pub. L. 115-91 §1634';
  const eff = (file.prohibition_effective_date ?? '').trim() || undefined;
  return (file.entities ?? []).map((e) => {
    const nameVerbatim = (e.name_verbatim ?? '').trim();
    return {
      source_id: 'ndaa-1634' as const,
      source_record_id: (e.slug ?? normalizeNameStripped(nameVerbatim)).trim(),
      name_canonical: normalizeName(nameVerbatim),
      name_canonical_stripped: normalizeNameStripped(nameVerbatim),
      name_verbatim: nameVerbatim,
      aliases: [],
      entity_type: 'organization' as const,
      addresses: [],
      programs: [e.covered_entity_class ?? '', e.note ?? ''].filter(Boolean) as string[],
      authority_citation: e.statute_paragraph ? `Pub. L. 115-91 §1634 (${e.statute_paragraph})` : authority,
      effective_date: eff,
      raw_record_pointer: { snapshot_filename: snapshotFilename },
    };
  });
}

// ─── FASCSA covered-article orders parser ────────────────────────────────────

interface FascsaOrdersFile {
  authority_citation?: string;
  orders?: Array<{
    order_id?: string;
    entity_name_verbatim?: string;
    covered_article?: string;
    issuing_authority?: string;
    cross_reference?: string;
    effective_date?: string;
    confirmed?: boolean;
    operator_note?: string;
  }>;
}

/**
 * Parse the operator-maintained FASCSA covered-article register. Each order
 * becomes an entity with `source_id: "fascsa"`. An order whose operator has not
 * yet confirmed an official FASC identifier (`confirmed === false`) is kept but
 * flagged with `requires_operator_input` so the gap is visible (W.W1 §11).
 */
export function parseFascsaOrders(
  file: FascsaOrdersFile,
  snapshotFilename = 'fascsa-orders.json',
): ProhibitedVendorEntity[] {
  const authority = file.authority_citation ?? '41 U.S.C. §1323 (FASCSA); FAR Subpart 4.23';
  const out: ProhibitedVendorEntity[] = [];
  const orders = file.orders ?? [];
  for (let i = 0; i < orders.length; i++) {
    const o = orders[i]!;
    const nameVerbatim = (o.entity_name_verbatim ?? '').trim();
    const entity: ProhibitedVendorEntity = {
      source_id: 'fascsa',
      source_record_id: (o.order_id ?? normalizeNameStripped(nameVerbatim)).trim(),
      name_canonical: nameVerbatim ? normalizeName(nameVerbatim) : '',
      name_canonical_stripped: nameVerbatim ? normalizeNameStripped(nameVerbatim) : '',
      name_verbatim: nameVerbatim,
      aliases: [],
      entity_type: 'organization',
      addresses: [],
      programs: [o.covered_article ?? '', o.issuing_authority ?? ''].filter(Boolean) as string[],
      authority_citation: authority,
      cross_reference: (o.cross_reference ?? '').trim() || undefined,
      effective_date: (o.effective_date ?? '').trim() || undefined,
      raw_record_pointer: { snapshot_filename: snapshotFilename, line_number: i + 1 },
    };
    if (!nameVerbatim) entity.requires_operator_input = 'missing-name-canonical';
    else if (o.confirmed === false) entity.requires_operator_input = 'fascsa-order-id-unconfirmed';
    out.push(entity);
  }
  return out;
}
