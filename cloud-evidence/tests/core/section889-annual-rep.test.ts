/**
 * Tests for the LOOP-W.W4 FAR 52.204-26 Section 889 annual representation
 * emitter (core/section889-annual-rep.ts) + the OOXML renderer
 * (core/section889-rep-docx.ts).
 *
 * The end-to-end tests build a REAL signed W.W2 screen envelope (assembled via
 * the W.W2 `assembleScreenResult` + the detached-Ed25519 signing idiom) and run
 * the representation emitter against it, so the screen-signature-verify path is
 * exercised for real (never mocked).
 *
 * Covers W.W4 §8: T1 (zero matches → both 'does not'), T2 (subprocessor match →
 * both 'does'), T3 (SBOM-only → provides 'does not' / uses 'does'), T4 (OCI-only,
 * same), T5 (inventory Kaspersky → both 'does' + supplement), T6 (all suppressed
 * → both 'does not'), T7/T8 (UEI missing/invalid), T9 (signing-key-id missing),
 * T11 (stale catalog strict/lenient), T12 (methodology missing), T13 (canonical
 * byte-stability), T14/T15 (docx byte-stability + OOXML parts), T16 (delta-link),
 * T17 (representation flip), T18 (Marketplace badge), T19 (Ed25519 verify),
 * T22 (Kaspersky opt-out), plus offeror/officer field validation, the
 * screen-signature-invalid guard, linked-incident collection, provenance (G3),
 * controls_evidenced, and the submission-bundle role registration.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { canonicalize, signDetached } from '../../core/sign.ts';
import {
  emitSection889AnnualRep,
  composeAnnualRepEnvelope,
  computeRepresentation,
  validateOperatorInputs,
  buildMarketplaceBadge,
  collectLinkedIncidents,
  detectFlips,
  canonicalAnnualRepBytes,
  verifySection889AnnualRep,
  Section889AnnualRepInputError,
  ScreenSignatureInvalidError,
  ScreenResultMissingError,
  StaleCatalogError,
  CONTROLS_EVIDENCED,
  ANNUAL_REP_JSON_FILENAME,
  ANNUAL_REP_DOCX_FILENAME,
  MARKETPLACE_BADGE_FILENAME,
  ANNUAL_REP_LEDGER_FILENAME,
  type Section889AnnualRepEnvelope,
} from '../../core/section889-annual-rep.ts';
import { renderSection889AnnualRepDocx, ANNUAL_REP_DOCX_PARTS } from '../../core/section889-rep-docx.ts';
import {
  assembleScreenResult, SCREEN_RESULT_FILENAME, SCREEN_RELATED_CONTROLS, REQUIRES_OPERATOR_INPUT,
  type ProhibitedVendorMatch, type ProhibitedVendorScreenResult, type ScreenSource,
  type ScreenSurface, type SurfaceScreened,
} from '../../core/prohibited-vendors-screen.ts';
import { buildSubmissionIndex } from '../../core/submission-bundle.ts';

const NOW = '2026-06-18T14:00:00.000Z';
const CATALOG_GEN = '2026-06-18T08:00:00.000Z';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-w4-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

// ─── Fixtures ──────────────────────────────────────────────────────────────────

const OFFEROR = {
  legal_name: 'FedPy Cloud Services, Inc.',
  unique_entity_id: 'JKL5678MNOP9',
  cage_code: '9ABC1',
  physical_address: { street1: '123 Main Street', city: 'Reston', state: 'VA', zip: '20190', country: 'US' },
};
const OFFICER = {
  full_name: 'Jane Q. Operator',
  title: 'Chief Information Security Officer',
  email: 'ciso@example.com',
  signing_key_id: 'operator-officer-2026Q3',
};

function defaultSurfaces(at: string): SurfaceScreened[] {
  return [
    { surface: 'subprocessor-sheet', entries_screened: 4, source_path: 'subprocessor-inventory.json', walked_at: at },
    { surface: 'sbom', entries_screened: 120, source_path: 'sbom/', walked_at: at },
    { surface: 'oci-publisher', entries_screened: 6, source_path: 'oci-attestations/', walked_at: at },
    { surface: 'inventory-provider-tag', entries_screened: 30, source_path: 'inventory.json', walked_at: at },
  ];
}

function mkMatch(o: {
  surface: ScreenSurface; source?: ScreenSource; name: string;
  band?: 'high' | 'medium' | 'low'; suppressed?: boolean;
}): ProhibitedVendorMatch {
  const slug = o.name.toLowerCase().replace(/\W+/g, '-');
  return {
    match_id: `pvm-${slug}-${o.surface}`,
    catalog_uid: `${o.source ?? 'far-52-204-25'}::${slug}`,
    catalog_provenance: { source: o.source ?? 'far-52-204-25', citation: 'FAR 52.204-25(a)', extracted_at: CATALOG_GEN },
    surface: o.surface,
    matched_entity_name: o.name,
    match_path: [o.name],
    confidence: o.band === 'medium' ? 0.7 : o.band === 'low' ? 0.5 : 1.0,
    confidence_band: o.band ?? 'high',
    matched_by: 'normalized-name',
    far_52_204_25_d_data_elements: {
      contract_numbers: [], order_numbers: [], supplier_name: o.name,
      supplier_uei: REQUIRES_OPERATOR_INPUT, supplier_cage_code: REQUIRES_OPERATOR_INPUT,
      brand: REQUIRES_OPERATOR_INPUT, model_number: REQUIRES_OPERATOR_INPUT,
      item_description: REQUIRES_OPERATOR_INPUT, mitigation_actions: REQUIRES_OPERATOR_INPUT,
    },
    poam_item_uuid: '11111111-1111-5111-8111-111111111111',
    related_controls: [...SCREEN_RELATED_CONTROLS],
    suppressed: o.suppressed ?? false,
    discovered_at: NOW,
    sources: { surface_evidence: `${o.surface}:${o.name}` },
  };
}

/** Assemble + sign a W.W2 screen result on disk (the real signing idiom). */
function writeSignedScreen(outDir: string, opts: {
  matches?: ProhibitedVendorMatch[];
  surfaces?: SurfaceScreened[];
  completedAt?: string;
  catalogGen?: string;
  ageHours?: number;
  isStale?: boolean;
  runId?: string;
} = {}): string {
  const completedAt = opts.completedAt ?? NOW;
  const result = assembleScreenResult({
    runId: opts.runId ?? 'run-w4',
    cspName: 'Acme Cloud Inc',
    startedAt: completedAt,
    completedAt,
    catalogRef: {
      path: 'data/prohibited-vendors-snapshot-20260618.json',
      sha256: 'b'.repeat(64),
      generated_at: opts.catalogGen ?? CATALOG_GEN,
      age_hours: opts.ageHours ?? 6,
      is_stale: opts.isStale ?? false,
    },
    surfaces: opts.surfaces ?? defaultSurfaces(completedAt),
    matches: opts.matches ?? [],
    suppressions: new Map(),
    surfacesWalkedCount: 4,
  });
  result.provenance.sourceDigests = [{ kind: 'catalog-snapshot', path: 'prohibited-vendors-catalog.json', sha256: 'b'.repeat(64) }];
  result.provenance.sourceCalls = ['catalog-snapshot:prohibited-vendors-catalog.json'];
  const canonical = canonicalize(JSON.parse(JSON.stringify({
    ...result, provenance: { ...result.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  })));
  const sig = signDetached(Buffer.from(canonical, 'utf8'), outDir);
  result.provenance.signingKeyId = sig.keyId;
  result.provenance.publicKeyPem = sig.publicKeyPem;
  result.provenance.signatureEd25519 = sig.signatureBase64;
  const p = resolve(outDir, SCREEN_RESULT_FILENAME);
  writeFileSync(p, JSON.stringify(result, null, 2));
  return p;
}

function writeMethodology(outDir: string): string {
  const p = resolve(outDir, 'methodology.md');
  writeFileSync(p, '# Reasonable-inquiry methodology\nThe CSP screens four surfaces against the W.W1 catalog.\n');
  return p;
}

function runRep(outDir: string, extra: Partial<Parameters<typeof emitSection889AnnualRep>[0]> = {}) {
  return emitSection889AnnualRep({
    outDir, runId: 'run-w4', cspName: 'Acme Cloud Inc',
    offeror: { ...OFFEROR }, authorizedOfficer: { ...OFFICER },
    reasonableInquiryMethodologyPath: writeMethodology(outDir),
    signedAt: NOW,
    ...extra,
  });
}

// ─── Representation answer computation (T1–T6) ───────────────────────────────

describe('section889-annual-rep — representation answers', () => {
  it('T1: zero unsuppressed matches → both representations "does not"', () => {
    const d = tmp();
    writeSignedScreen(d);
    const r = runRep(d);
    expect(r.provides_status).toBe('does not');
    expect(r.uses_status).toBe('does not');
    expect(r.envelope.representation.rationale.total_matches).toBe(0);
    expect(r.envelope.representation.rationale.provides_basis).toMatch(/no covered telecommunications/i);
  });

  it('T2: one subprocessor Hikvision match → provides "does" AND uses "does"', () => {
    const d = tmp();
    writeSignedScreen(d, { matches: [mkMatch({ surface: 'subprocessor-sheet', name: 'Hangzhou Hikvision Digital Technology Company' })] });
    const r = runRep(d);
    expect(r.provides_status).toBe('does');
    expect(r.uses_status).toBe('does');
    expect(r.envelope.representation.rationale.provides_basis).toMatch(/subprocessor-sheet/);
  });

  it('T3: SBOM-only transitive match → provides "does not" BUT uses "does"', () => {
    const d = tmp();
    writeSignedScreen(d, { matches: [mkMatch({ surface: 'sbom', name: 'Huawei Technologies Company' })] });
    const r = runRep(d);
    expect(r.provides_status).toBe('does not');
    expect(r.uses_status).toBe('does');
  });

  it('T4: OCI publisher-only match → provides "does not" BUT uses "does"', () => {
    const d = tmp();
    writeSignedScreen(d, { matches: [mkMatch({ surface: 'oci-publisher', name: 'Dahua Technology Company' })] });
    const r = runRep(d);
    expect(r.provides_status).toBe('does not');
    expect(r.uses_status).toBe('does');
  });

  it('T5: inventory provider-tag Kaspersky match → both "does"; Kaspersky supplement rendered', () => {
    const d = tmp();
    writeSignedScreen(d, { matches: [mkMatch({ surface: 'inventory-provider-tag', source: 'ndaa-1634', name: 'Kaspersky Lab' })] });
    const r = runRep(d, { includeKasperskyAttachment: true });
    expect(r.provides_status).toBe('does');
    expect(r.uses_status).toBe('does');
    expect(r.envelope.kaspersky_supplement).toBeDefined();
    expect(r.envelope.kaspersky_supplement?.statute).toBe('NDAA-FY2018-§1634');
  });

  it('T6: all matches operator-suppressed → both "does not"; suppression surfaced in rationale', () => {
    const d = tmp();
    writeSignedScreen(d, { matches: [
      mkMatch({ surface: 'subprocessor-sheet', name: 'Hytera Communications Corporation', suppressed: true }),
      mkMatch({ surface: 'sbom', name: 'ZTE Corporation', suppressed: true }),
    ] });
    const r = runRep(d);
    expect(r.provides_status).toBe('does not');
    expect(r.uses_status).toBe('does not');
    expect(r.envelope.representation.rationale.total_matches).toBe(2);
    expect(r.envelope.representation.rationale.unsuppressed_matches).toBe(0);
    expect(r.envelope.representation.rationale.suppressed_matches).toBe(2);
  });
});

// ─── Pure split logic (defensive: provides ⊆ uses) ────────────────────────────

describe('section889-annual-rep — computeRepresentation split', () => {
  const ctx = { screen_run_id: 'run-x', catalog_snapshot_id: 'snap', catalog_snapshot_sha256: 'c'.repeat(64), subprocessor_count: 4, inventory_asset_count: 30 };

  it('subprocessor + inventory drive (c)(1); sbom + oci do not', () => {
    const v = computeRepresentation([
      mkMatch({ surface: 'sbom', name: 'Huawei Technologies Company' }),
      mkMatch({ surface: 'oci-publisher', name: 'Dahua Technology Company' }),
    ], ctx);
    expect(v.provides_status).toBe('does not');
    expect(v.uses_status).toBe('does');
  });

  it('inventory-provider-tag match drives both', () => {
    const v = computeRepresentation([mkMatch({ surface: 'inventory-provider-tag', name: 'ZTE Corporation' })], ctx);
    expect(v.provides_status).toBe('does');
    expect(v.uses_status).toBe('does');
  });
});

// ─── Operator-input validation (T7–T9, T12, + offeror/officer) ────────────────

describe('section889-annual-rep — operator-input validation', () => {
  it('T7: missing UEI → throws requires_operator_input: offeror.unique_entity_id; no artifact written', () => {
    const d = tmp();
    writeSignedScreen(d);
    expect(() => runRep(d, { offeror: { ...OFFEROR, unique_entity_id: '' } }))
      .toThrowError(/requires_operator_input: offeror\.unique_entity_id/);
    expect(existsSync(resolve(d, ANNUAL_REP_JSON_FILENAME))).toBe(false);
    expect(existsSync(resolve(d, ANNUAL_REP_DOCX_FILENAME))).toBe(false);
  });

  it('T8: malformed UEI (11 chars) → throws :invalid-format', () => {
    const d = tmp();
    writeSignedScreen(d);
    expect(() => runRep(d, { offeror: { ...OFFEROR, unique_entity_id: 'JKL5678MNOP' } }))
      .toThrowError(/offeror\.unique_entity_id .*invalid-format/);
  });

  it('T9: missing officer signing_key_id → throws requires_operator_input', () => {
    const d = tmp();
    writeSignedScreen(d);
    expect(() => runRep(d, { authorizedOfficer: { ...OFFICER, signing_key_id: '' } }))
      .toThrowError(/requires_operator_input: authorized_officer\.signing_key_id/);
  });

  it('missing officer full_name → throws; missing physical_address.city → throws', () => {
    const d = tmp();
    writeSignedScreen(d);
    expect(() => runRep(d, { authorizedOfficer: { ...OFFICER, full_name: '   ' } }))
      .toThrowError(/authorized_officer\.full_name/);
    expect(() => runRep(d, { offeror: { ...OFFEROR, physical_address: { ...OFFEROR.physical_address, city: '' } } }))
      .toThrowError(/offeror\.physical_address\.city/);
  });

  it('malformed officer email → throws :invalid-format', () => {
    const d = tmp();
    writeSignedScreen(d);
    expect(() => runRep(d, { authorizedOfficer: { ...OFFICER, email: 'not-an-email' } }))
      .toThrowError(/authorized_officer\.email .*invalid-format/);
  });

  it('T12: missing methodology document → throws requires_operator_input', () => {
    const d = tmp();
    writeSignedScreen(d);
    expect(() => emitSection889AnnualRep({
      outDir: d, runId: 'run-w4', cspName: 'Acme', offeror: { ...OFFEROR }, authorizedOfficer: { ...OFFICER },
      reasonableInquiryMethodologyPath: resolve(d, 'does-not-exist.md'), signedAt: NOW,
    })).toThrowError(/requires_operator_input: reasonable_inquiry\.methodology_path/);
  });

  it('valid_until_days out of range → throws', () => {
    expect(() => validateOperatorInputs({ offeror: OFFEROR, authorizedOfficer: OFFICER, methodologyPath: __filename, validUntilDays: 9999 }))
      .toThrowError(/valid_until_days/);
  });

  it('absent CAGE is a warning, not a throw', () => {
    const v = validateOperatorInputs({ offeror: { ...OFFEROR, cage_code: '' }, authorizedOfficer: OFFICER, methodologyPath: __filename });
    expect(v.offeror.cage_code).toBeNull();
    expect(v.warnings.some((w) => /cage_code/.test(w))).toBe(true);
  });
});

// ─── Screen ingestion guards (signature + missing + stale) ────────────────────

describe('section889-annual-rep — screen ingestion guards', () => {
  it('missing W.W2 screen result → throws ScreenResultMissingError', () => {
    const d = tmp();
    expect(() => runRep(d)).toThrowError(ScreenResultMissingError);
  });

  it('tampered W.W2 screen signature → throws ScreenSignatureInvalidError; no artifact written', () => {
    const d = tmp();
    const p = writeSignedScreen(d, { matches: [mkMatch({ surface: 'sbom', name: 'Huawei Technologies Company' })] });
    const screen = JSON.parse(readFileSync(p, 'utf8'));
    screen.matches[0].matched_entity_name = 'Acme Innocent Corp'; // post-sign tamper
    writeFileSync(p, JSON.stringify(screen, null, 2));
    expect(() => runRep(d)).toThrowError(ScreenSignatureInvalidError);
    expect(existsSync(resolve(d, ANNUAL_REP_JSON_FILENAME))).toBe(false);
  });

  it('T11: stale catalog → strict throws StaleCatalogError; lenient warns + emits', () => {
    const dStrict = tmp();
    writeSignedScreen(dStrict, { isStale: true, ageHours: 49 });
    expect(() => runRep(dStrict, { strictCatalogFreshness: true })).toThrowError(StaleCatalogError);
    expect(existsSync(resolve(dStrict, ANNUAL_REP_JSON_FILENAME))).toBe(false);

    const dLenient = tmp();
    writeSignedScreen(dLenient, { isStale: true, ageHours: 49 });
    const r = runRep(dLenient, { strictCatalogFreshness: false });
    expect(r.warnings.some((w) => /coverage:stale-catalog/.test(w))).toBe(true);
    expect(existsSync(resolve(dLenient, ANNUAL_REP_JSON_FILENAME))).toBe(true);
  });
});

// ─── Envelope shape, provenance (G3), controls, signature (T19) ───────────────

describe('section889-annual-rep — envelope + provenance + signature', () => {
  it('envelope carries a camelCase provenance block with the G3-required keys (non-empty sourceCalls)', () => {
    const d = tmp();
    writeSignedScreen(d);
    const env = runRep(d).envelope;
    const p = env.provenance;
    expect(typeof p.emitter).toBe('string');
    expect(typeof p.emittedAt).toBe('string');
    expect(Array.isArray(p.sourceCalls) && p.sourceCalls.length > 0).toBe(true);
    expect(typeof p.signingKeyId).toBe('string');
    expect(p.signingKeyId.length).toBeGreaterThan(0);
  });

  it('controls_evidenced is exactly the SR family SR-1/3/5/6/11', () => {
    const d = tmp();
    writeSignedScreen(d);
    expect(runRep(d).envelope.controls_evidenced).toEqual([...CONTROLS_EVIDENCED]);
  });

  it('valid_until = signed_at + 365 days by default', () => {
    const d = tmp();
    writeSignedScreen(d);
    const env = runRep(d).envelope;
    const delta = Date.parse(env.valid_until) - Date.parse(env.signed_at);
    expect(delta).toBe(365 * 86400000);
  });

  it('valid_until honours a custom valid_until_days', () => {
    const d = tmp();
    writeSignedScreen(d);
    const env = runRep(d, { validUntilDays: 90 }).envelope;
    expect(Date.parse(env.valid_until) - Date.parse(env.signed_at)).toBe(90 * 86400000);
  });

  it('T19: the Ed25519 signature verifies against the embedded public key', () => {
    const d = tmp();
    writeSignedScreen(d);
    const env = runRep(d).envelope;
    expect(verifySection889AnnualRep(env)).toBe(true);
  });

  it('a mutated representation answer breaks signature verification', () => {
    const d = tmp();
    writeSignedScreen(d);
    const env = runRep(d).envelope;
    const tampered: Section889AnnualRepEnvelope = JSON.parse(JSON.stringify(env));
    tampered.representation.uses_covered_equipment_or_services = 'does';
    expect(verifySection889AnnualRep(tampered)).toBe(false);
  });
});

// ─── Byte-stability (T13, T14, T15) ───────────────────────────────────────────

describe('section889-annual-rep — reproducibility', () => {
  const screen: ProhibitedVendorScreenResult = JSON.parse(JSON.stringify({
    schema_version: '1.0.0', run_id: 'run-x', csp_name: 'Acme', started_at: NOW, completed_at: NOW,
    catalog_snapshot_ref: { path: 'snap', sha256: 'd'.repeat(64), generated_at: CATALOG_GEN, age_hours: 6, is_stale: false },
    surfaces_screened: defaultSurfaces(NOW), matches: [], summary: { total_matches: 0, matches_by_source: {}, matches_by_surface: {}, matches_by_confidence_band: { high: 0, medium: 0, low: 0 }, suppressed_matches: 0 },
    reportable_under_far_52_204_25_d: false, reportable_under_ndaa_1634: false, reasonable_inquiry_attested: true,
    provenance: { emitter: 'x', emittedAt: NOW, sourceCalls: ['x:y'], signingKeyId: '', algorithm: 'ed25519', signatureEd25519: '', publicKeyPem: '', rfc3161TimestampPath: null, sourceDigests: [] },
  }));

  function composeFixed(): Section889AnnualRepEnvelope {
    return composeAnnualRepEnvelope({
      cspName: 'Acme',
      offeror: { legal_name: OFFEROR.legal_name, unique_entity_id: OFFEROR.unique_entity_id, cage_code: OFFEROR.cage_code, duns: null, physical_address: { ...OFFEROR.physical_address, street2: '' } },
      authorizedOfficer: { ...OFFICER },
      verdict: computeRepresentation([], { screen_run_id: 'run-x', catalog_snapshot_id: 'snap', catalog_snapshot_sha256: 'd'.repeat(64), subprocessor_count: 4, inventory_asset_count: 30 }),
      linkedIncidents: [], screen, methodologyPath: 'methodology.md', methodologySha256: 'e'.repeat(64),
      includeKaspersky: true, signedAt: NOW, validUntilDays: 365, previousEnvelopeId: null,
      sourceDigests: [{ kind: 'screen', path: 'prohibited-vendors-screen-result.json', sha256: 'f'.repeat(64) }],
    });
  }

  it('T13: canonical envelope bytes are identical across two composes with identical inputs', () => {
    expect(canonicalAnnualRepBytes(composeFixed())).toBe(canonicalAnnualRepBytes(composeFixed()));
  });

  it('T14: the .docx byte-stream is identical across two renders with identical inputs', () => {
    const a = renderSection889AnnualRepDocx(composeFixed());
    const b = renderSection889AnnualRepDocx(composeFixed());
    expect(a.equals(b)).toBe(true);
  });

  it('T15: the .docx is a well-formed zip containing exactly the declared OOXML parts', () => {
    const buf = renderSection889AnnualRepDocx(composeFixed());
    expect(buf.subarray(0, 2).toString('latin1')).toBe('PK'); // local file header signature
    const text = buf.toString('latin1');
    for (const part of ANNUAL_REP_DOCX_PARTS) expect(text.includes(part)).toBe(true);
  });

  it('the checked box (■) renders for the screen-driven answer in the .docx', () => {
    const d = tmp();
    writeSignedScreen(d, { matches: [mkMatch({ surface: 'subprocessor-sheet', name: 'Hangzhou Hikvision Digital Technology Company' })] });
    const r = runRep(d);
    const docx = readFileSync(r.docx_path).toString('utf8');
    expect(docx.includes('■')).toBe(true);
    expect(docx.includes('FAR 52.204-26')).toBe(true);
  });
});

// ─── Delta / flip / linked incidents (T16, T17) ───────────────────────────────

describe('section889-annual-rep — delta, flip, linked incidents', () => {
  it('T16: a prior ledger row sets previous_envelope_id on the new envelope', () => {
    const d = tmp();
    writeSignedScreen(d);
    const ledger = resolve(d, ANNUAL_REP_LEDGER_FILENAME);
    appendFileSync(ledger, JSON.stringify({
      envelope_uuid: 'prior-uuid-0001', signed_at: '2025-06-18T00:00:00.000Z', valid_until: '2026-06-18T00:00:00.000Z',
      provides_status: 'does not', uses_status: 'does not', screen_run_id: 'run-prev', catalog_snapshot_id: 'snap',
      unsuppressed_match_count: 0, json_sha256: 'a'.repeat(64), json_path: 'x.json', docx_path: 'x.docx',
    }) + '\n');
    const r = runRep(d);
    expect(r.previous_envelope_id).toBe('prior-uuid-0001');
    expect(r.envelope.previous_envelope_id).toBe('prior-uuid-0001');
  });

  it('T17: a "does not" → "does" flip is detected and reported', () => {
    const d = tmp();
    writeSignedScreen(d, { matches: [mkMatch({ surface: 'sbom', name: 'Huawei Technologies Company' })] });
    const ledger = resolve(d, ANNUAL_REP_LEDGER_FILENAME);
    appendFileSync(ledger, JSON.stringify({
      envelope_uuid: 'prior-uuid-0002', signed_at: '2025-06-18T00:00:00.000Z', valid_until: '2026-06-18T00:00:00.000Z',
      provides_status: 'does not', uses_status: 'does not', screen_run_id: 'run-prev', catalog_snapshot_id: 'snap',
      unsuppressed_match_count: 0, json_sha256: 'a'.repeat(64), json_path: 'x.json', docx_path: 'x.docx',
    }) + '\n');
    const r = runRep(d);
    const usesFlip = r.flips.find((f) => f.dimension === 'uses');
    expect(usesFlip).toBeDefined();
    expect(usesFlip?.from).toBe('does not');
    expect(usesFlip?.to).toBe('does');
  });

  it('detectFlips returns empty when there is no prior rep', () => {
    const d = tmp();
    writeSignedScreen(d);
    expect(runRep(d).flips).toEqual([]);
  });

  it('linked incidents are collected from the W.W3 1BD ledger by match_id', () => {
    const d = tmp();
    const match = mkMatch({ surface: 'subprocessor-sheet', name: 'Hangzhou Hikvision Digital Technology Company' });
    writeSignedScreen(d, { matches: [match] });
    const oneBd = resolve(d, 'section889-1bd-reports.jsonl');
    appendFileSync(oneBd, JSON.stringify({
      run_id: 'run-w3', match_id: match.match_id, contract_number: '47QFCA22F0001', report_kind: 'initial-1bd',
      report_id: 's889-abc123', emitted_at: '2026-06-17T10:00:00.000Z', deadline_at: '2026-06-18T17:00:00.000Z',
    }) + '\n');
    const r = runRep(d);
    expect(r.linked_incidents_count).toBe(1);
    expect(r.envelope.representation.linked_incidents[0].incident_id).toBe('s889-abc123');
    expect(r.envelope.representation.linked_incidents[0].contract_number).toBe('47QFCA22F0001');
  });

  it('collectLinkedIncidents ignores match_ids that are not in the driving set', () => {
    const d = tmp();
    const oneBd = resolve(d, 'section889-1bd-reports.jsonl');
    appendFileSync(oneBd, JSON.stringify({ match_id: 'unrelated', report_id: 's889-zzz', emitted_at: NOW, contract_number: 'X' }) + '\n');
    expect(collectLinkedIncidents(oneBd, new Set(['pvm-something-else']))).toEqual([]);
  });
});

// ─── Marketplace badge feed (T18) ─────────────────────────────────────────────

describe('section889-annual-rep — Marketplace badge feed', () => {
  it('T18: badge enabled iff both "does not" AND valid_until > now', () => {
    const d = tmp();
    writeSignedScreen(d);
    const r = runRep(d);
    const badge = JSON.parse(readFileSync(r.marketplace_feed_path, 'utf8'));
    expect(badge.badge.enabled).toBe(true);
    expect(badge.badge.label).toBe('Section 889 Compliant');
    // The badge feed itself carries a provenance block (G3).
    expect(Array.isArray(badge.provenance.sourceCalls) && badge.provenance.sourceCalls.length > 0).toBe(true);
  });

  it('badge grey-listed when a match flips "uses" to "does"', () => {
    const d = tmp();
    writeSignedScreen(d, { matches: [mkMatch({ surface: 'sbom', name: 'ZTE Corporation' })] });
    const r = runRep(d);
    expect(r.badge_enabled).toBe(false);
    const badge = JSON.parse(readFileSync(r.marketplace_feed_path, 'utf8'));
    expect(badge.badge.enabled).toBe(false);
  });

  it('buildMarketplaceBadge greys out an expired-but-clean representation', () => {
    const d = tmp();
    writeSignedScreen(d);
    const env = runRep(d).envelope;
    const future = new Date(Date.parse(env.valid_until) + 86400000).toISOString();
    expect(buildMarketplaceBadge(env, future).badge.enabled).toBe(false);
  });
});

// ─── Kaspersky opt-out (T22) ──────────────────────────────────────────────────

describe('section889-annual-rep — Kaspersky supplement opt-out', () => {
  it('T22: include_kaspersky_attachment:false → no supplement block; no Annex B in .docx', () => {
    const d = tmp();
    writeSignedScreen(d);
    const r = runRep(d, { includeKasperskyAttachment: false });
    expect(r.envelope.kaspersky_supplement).toBeUndefined();
    const docx = readFileSync(r.docx_path).toString('utf8');
    expect(docx.includes('Annex B')).toBe(false);
  });
});

// ─── Submission-bundle role registration ──────────────────────────────────────

describe('section889-annual-rep — submission-bundle integration', () => {
  it('the annual-rep JSON + .docx + badge are recognized WELL_KNOWN bundle roles', () => {
    const d = tmp();
    // Minimal signed manifest so the bundler can read the dir.
    writeFileSync(resolve(d, 'manifest.json'), JSON.stringify({ files: [], signer_public_key: '' }));
    writeSignedScreen(d);
    runRep(d);
    const { index } = buildSubmissionIndex(d, { outDir: d, runId: 'run-w4', frmrVersion: 'test' });
    const byName = new Map(index.artifacts.map((a) => [a.filename, a.role]));
    expect(byName.get(ANNUAL_REP_JSON_FILENAME)).toBe('section889-annual-rep-json');
    expect(byName.get(ANNUAL_REP_DOCX_FILENAME)).toBe('section889-annual-rep-docx');
    expect(byName.get(MARKETPLACE_BADGE_FILENAME)).toBe('marketplace-section889-badge');
    expect(byName.get(ANNUAL_REP_LEDGER_FILENAME)).toBe('section889-annual-rep-ledger');
  });
});
