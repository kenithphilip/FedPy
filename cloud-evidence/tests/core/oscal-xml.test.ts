/**
 * Tests for core/oscal-xml.ts — the OSCAL JSON→XML converter (OSC-3).
 *
 * Three axes of coverage:
 *   1. Mapping rules: attributes vs elements, plural→singular array
 *      handling, prose wrapping for description/remarks.
 *   2. Escaping + well-formedness: the converter never emits invalid XML
 *      regardless of input content (quotes, ampersands, angle brackets).
 *   3. End-to-end: both `emitOscalAssessmentResults` and `emitOscalSsp`
 *      drop a sibling `.xml` file by default that contains the model's
 *      root element with the OSCAL namespace.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { oscalJsonToXml } from '../../core/oscal-xml.ts';
import { emitOscalAssessmentResults } from '../../core/oscal.ts';
import { emitOscalSsp } from '../../core/oscal-ssp.ts';

describe('oscalJsonToXml — mapping rules', () => {
  it('emits the OSCAL namespace + FedRAMP alias on the root element', () => {
    const xml = oscalJsonToXml({ 'assessment-results': { uuid: 'u1' } });
    expect(xml).toContain('xmlns="http://csrc.nist.gov/ns/oscal/1.0"');
    expect(xml).toContain('xmlns:fedramp="https://fedramp.gov/ns/oscal"');
    expect(xml).toContain('<assessment-results');
  });

  it('promotes flag keys (uuid, name, value, class, href, …) to attributes', () => {
    const xml = oscalJsonToXml({
      'assessment-results': {
        uuid: '11111111-1111-1111-1111-111111111111',
        metadata: {
          title: 't',
          props: [{ name: 'sev', value: 'high', ns: 'urn:x', class: 'c' }],
          links: [{ href: 'https://example.test/a', rel: 'reference' }],
        },
      },
    });
    expect(xml).toContain('uuid="11111111-1111-1111-1111-111111111111"');
    expect(xml).toContain('<prop name="sev" value="high" ns="urn:x" class="c"/>');
    expect(xml).toContain('<link href="https://example.test/a" rel="reference"/>');
  });

  it('renders arrays as repeated singular elements per PLURAL_TO_SINGULAR', () => {
    const xml = oscalJsonToXml({
      'assessment-results': {
        uuid: 'u',
        results: [
          { uuid: 'r1', title: 'A', findings: [{ uuid: 'f1' }, { uuid: 'f2' }] },
          { uuid: 'r2', title: 'B' },
        ],
      },
    });
    // results → result; findings → finding
    const resultMatches = xml.match(/<result\b/g) ?? [];
    expect(resultMatches.length).toBe(2);
    const findingMatches = xml.match(/<finding\b/g) ?? [];
    expect(findingMatches.length).toBe(2);
    // never emit a literal <results> wrapper or <findings> wrapper
    expect(xml).not.toContain('<results');
    expect(xml).not.toContain('<findings');
  });

  it('wraps description + remarks bodies in <p>...</p> per OSCAL prose convention', () => {
    const xml = oscalJsonToXml({
      'assessment-results': {
        uuid: 'u',
        results: [{ uuid: 'r', title: 't', description: 'Hello world.', remarks: 'After action.' }],
      },
    });
    expect(xml).toContain('<description>');
    expect(xml).toContain('<p>Hello world.</p>');
    expect(xml).toContain('<remarks>');
    expect(xml).toContain('<p>After action.</p>');
  });

  it('emits singular string-array elements (party-uuids, methods) verbatim', () => {
    const xml = oscalJsonToXml({
      'assessment-results': {
        uuid: 'u',
        results: [{
          uuid: 'r',
          observations: [{
            uuid: 'o', methods: ['EXAMINE', 'TEST'], collected: '2026-01-01T00:00:00Z',
            description: 'd',
          }],
          'responsible-parties': [{ 'role-id': 'assessor', 'party-uuids': ['p1', 'p2'] }],
        }],
      },
    });
    expect(xml).toContain('<method>EXAMINE</method>');
    expect(xml).toContain('<method>TEST</method>');
    expect(xml).toContain('<responsible-party role-id="assessor">');
    expect(xml).toContain('<party-uuid>p1</party-uuid>');
    expect(xml).toContain('<party-uuid>p2</party-uuid>');
  });

  it('escapes ampersands, angle brackets, quotes, and apostrophes', () => {
    const xml = oscalJsonToXml({
      'assessment-results': {
        uuid: 'u',
        metadata: {
          title: 'A & B <inline> "quoted" \'apos\'',
          props: [{ name: 'n', value: 'v & < > " \'' }],
        },
      },
    });
    // Body content
    expect(xml).toContain('A &amp; B &lt;inline&gt; &quot;quoted&quot; &apos;apos&apos;');
    // Attribute content
    expect(xml).toContain('value="v &amp; &lt; &gt; &quot; &apos;"');
  });

  it('starts with the XML declaration and ends with a newline', () => {
    const xml = oscalJsonToXml({ 'assessment-results': { uuid: 'u' } });
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>\n')).toBe(true);
    expect(xml.endsWith('\n')).toBe(true);
  });

  it('throws when the top-level document has zero or multiple wrapper keys', () => {
    expect(() => oscalJsonToXml({})).toThrow(/single top-level wrapper key/);
    expect(() => oscalJsonToXml({ a: {}, b: {} })).toThrow(/single top-level wrapper key/);
  });

  it('skips undefined / null fields entirely', () => {
    const xml = oscalJsonToXml({
      'assessment-results': {
        uuid: 'u',
        metadata: { title: 't', version: '1', 'oscal-version': '1.1.2' },
        // Optional fields explicitly null/undefined should NOT appear in XML.
        'back-matter': null as unknown as undefined,
      },
    });
    expect(xml).not.toContain('<back-matter');
  });

  it('falls through plural→singular heuristic when the key is not in the table', () => {
    // "widgets" isn't in PLURAL_TO_SINGULAR, so the heuristic strips the trailing 's'.
    const xml = oscalJsonToXml({ root: { widgets: [{ id: 'w1' }] } });
    expect(xml).toContain('<widget id="w1"/>');
  });
});

describe('oscalJsonToXml — well-formedness invariants', () => {
  it('produces balanced open/close tag counts for arbitrary nested input', () => {
    const xml = oscalJsonToXml({
      'assessment-results': {
        uuid: 'u',
        metadata: { title: 't', version: '1', 'oscal-version': '1.1.2' },
        'import-ap': { href: '#x' },
        results: [{
          uuid: 'r', title: 'tt', description: 'd', start: '2026-01-01T00:00:00Z',
          'reviewed-controls': { 'control-selections': [{ 'include-controls': [{ 'control-id': 'ac-1' }] }] },
          findings: [{ uuid: 'f', title: 'ft', description: 'fd', target: { type: 'objective-id', 'target-id': 'x', status: { state: 'satisfied' } } }],
          observations: [{ uuid: 'o', description: 'od', methods: ['EXAMINE'], collected: '2026-01-01T00:00:00Z' }],
        }],
      },
    });
    // Count opens — exclude the XML decl + self-closing tags from the close count
    const opens = xml.match(/<[a-z][^!?/][^>]*[^/]>/g) ?? [];
    const closes = xml.match(/<\/[a-z][^>]*>/g) ?? [];
    expect(opens.length).toBe(closes.length);
  });
});

describe('emit*.xml — end-to-end sibling-file generation', () => {
  function makeKsiEvidence(outDir: string): void {
    const evidence = {
      ksi_id: 'KSI-IAM-MFA', ksi_name: 'MFA', ksi_statement: 'enforce mfa',
      scope: 'CLOUD' as const,
      frmr_version: 'test', run_id: '00000000-0000-0000-0000-000000000000',
      collected_at: '2026-01-01T00:00:00.000Z',
      providers: [{
        provider: 'aws',
        account_id: '123456789012',
        evidence: [], findings: [],
        warnings: [],
      }],
      rollup: { pass: true, passing_findings: 0, failing_findings: 0, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
    };
    writeFileSync(join(outDir, 'KSI-IAM-MFA.json'), JSON.stringify(evidence));
  }

  it('emitOscalAssessmentResults writes assessment-results.xml alongside the JSON by default', () => {
    const dir = mkdtempSync(join(tmpdir(), 'oscal-xml-ar-'));
    try {
      makeKsiEvidence(dir);
      const r = emitOscalAssessmentResults({ outDir: dir, runId: '00000000-0000-0000-0000-000000000000', frmrVersion: 'test' });
      expect(r.xml_path).toBeDefined();
      expect(existsSync(r.xml_path!)).toBe(true);
      const xml = readFileSync(r.xml_path!, 'utf8');
      expect(xml).toContain('<assessment-results');
      expect(xml).toContain('xmlns="http://csrc.nist.gov/ns/oscal/1.0"');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('honours CLOUD_EVIDENCE_DISABLE_OSCAL_XML=1 to skip the XML', () => {
    const dir = mkdtempSync(join(tmpdir(), 'oscal-xml-off-'));
    const prev = process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML;
    process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML = '1';
    try {
      makeKsiEvidence(dir);
      const r = emitOscalAssessmentResults({ outDir: dir, runId: '00000000-0000-0000-0000-000000000000', frmrVersion: 'test' });
      expect(r.xml_path).toBeUndefined();
      expect(existsSync(resolve(dir, 'assessment-results.xml'))).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML;
      else process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML = prev;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('emitOscalSsp writes ssp.xml alongside the JSON by default', () => {
    const dir = mkdtempSync(join(tmpdir(), 'oscal-xml-ssp-'));
    try {
      const r = emitOscalSsp({
        outDir: dir,
        runId: '00000000-0000-0000-0000-000000000000',
        frmrVersion: 'test',
        impactLevel: 'Moderate',
        systemName: 'Test System',
        systemShortName: 'test-sys',
        systemDescription: 'A test system',
        organizationName: 'Test Org',
      });
      expect(r.xml_path).toBeDefined();
      expect(existsSync(r.xml_path!)).toBe(true);
      const xml = readFileSync(r.xml_path!, 'utf8');
      expect(xml).toContain('<system-security-plan');
      expect(xml).toContain('xmlns="http://csrc.nist.gov/ns/oscal/1.0"');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
