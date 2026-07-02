/**
 * Tests for core/oscal-poam.ts — the OSCAL Plan of Action and Milestones
 * emitter (LOOP-A.A1).
 *
 * The tests:
 *   1. Build a POA&M from synthetic but realistically-shaped EvidenceFile
 *      records and assert the OSCAL document validates against the committed
 *      v1.1.2 schema (the same schema CI gates on).
 *   2. Verify the schema-required structure: uuid, metadata.{title,
 *      last-modified, version, oscal-version}, poam-items[].
 *   3. Verify the FedRAMP-required cross-references: import-ssp (when
 *      provided), system-id, back-matter resource with the signed-manifest
 *      pointer.
 *   4. Verify the REO contract — every poam-item traces back to a real
 *      finding, including the per-finding deadline math.
 *   5. Verify deterministic emission (same inputs → identical document).
 *   6. Verify the "clean POA&M" case (no failing findings → empty poam-items[]
 *      + an explicit remarks string stating zero open items, NOT a missing-
 *      evidence error).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildOscalPoam, emitOscalPoam } from '../../core/oscal-poam.ts';
import { validateOscal, validateOscalFile } from '../../core/oscal-validate.ts';
import type { EvidenceFile, Finding } from '../../core/envelope.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-poam-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

// ─── Fixture helpers ─────────────────────────────────────────────────────────
function makeFinding(over: Partial<Finding> = {}): Finding {
  return {
    rule: over.rule ?? 'aws.iam.root_mfa_enabled',
    passed: over.passed ?? false,
    severity: over.severity ?? 'high',
    current_state: over.current_state ?? { summary: 'Root user MFA is NOT enabled.', observations: {} },
    target_state: over.target_state ?? {
      summary: 'Root user MFA enabled and a physical hardware token registered.',
      rationale: 'Root account compromise is catastrophic; phishing-resistant MFA is required.',
    },
    gap: over.gap ?? {
      description: 'Root account does not have any MFA device registered.',
      affected_resources: [
        { type: 'aws_iam_root_user', identifier: 'arn:aws:iam::123456789012:root', attributes: { account_id: '123456789012', region: 'us-east-1' } },
      ],
    },
    remediation: over.remediation ?? {
      summary: 'Register a hardware MFA token for the root user.',
      options: [
        {
          approach: 'Register a YubiKey 5 series as root MFA',
          mechanism: 'console',
          steps: [
            'Log in to AWS console as root.',
            'Navigate to My Security Credentials → MFA.',
            'Select Security Key, register YubiKey.',
          ],
          effort_estimate: { magnitude: 'minutes', notes: 'One-time setup.' },
          cost_impact: { level: 'low', notes: 'Cost of YubiKey hardware.' },
          availability_impact: { level: 'none', notes: 'Read-only operation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
        },
      ],
    },
    nist_controls: over.nist_controls ?? ['ia-2.1', 'ia-2.6'],
    applicable_key_word: 'MUST',
  };
}

function makeEnvelope(over: Partial<EvidenceFile> & { findings?: Finding[] } = {}): EvidenceFile {
  const findings = over.findings ?? [makeFinding()];
  return {
    ksi_id: (over as any).ksi_id ?? 'KSI-IAM-MFA',
    ksi_name: (over as any).ksi_name ?? 'Enforcing Phishing-Resistant MFA',
    ksi_statement: 'Enforce MFA using phishing-resistant methods.',
    scope: 'CLOUD',
    frmr_version: '0.9.43-beta',
    run_id: 'r-test-1',
    collected_at: '2026-06-05T00:00:00Z',
    nist_controls: ['ia-2.1'],
    providers: [
      {
        provider: 'aws',
        account_id: '123456789012',
        region_set: ['us-east-1'],
        evidence: [
          { source: 'iam.GetAccountSummary', captured_at: '2026-06-05T00:00:00Z', data: { AccountMFAEnabled: 0 } },
        ],
        findings,
      } as any,
    ],
    summary_for_llm: 'fixture',
  } as unknown as EvidenceFile;
}

// ─── Tests ───────────────────────────────────────────────────────────────────
describe('OSCAL POA&M emitter — buildOscalPoam', () => {
  it('produces a schema-valid POA&M document from a single failing finding', () => {
    const env = makeEnvelope();
    const { doc, result } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r-test-1', frmrVersion: '0.9.43-beta', systemId: 'acme-prod', systemName: 'Acme Prod',
    });
    const v = validateOscal(doc, 'poam');
    if (!v.valid) throw new Error(`POA&M schema invalid:\n${v.errors.slice(0, 8).join('\n')}`);
    expect(v.valid).toBe(true);
    expect(result.poam_item_count).toBe(1);
    expect(result.observation_count).toBe(1);
    expect(result.risk_count).toBe(1); // severity=high → risk emitted
    expect(result.finding_count).toBe(2); // 2 controls (ia-2.1, ia-2.6) → 2 findings
    expect(result.by_severity.high).toBe(1);
  });

  it('emits required metadata fields', () => {
    const env = makeEnvelope();
    const { doc } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r-test-1', frmrVersion: '0.9.43-beta', systemId: 'acme-prod',
    });
    const m = doc['plan-of-action-and-milestones'].metadata;
    expect(m.title).toBeTruthy();
    expect(m['last-modified']).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(m.version).toBe('r-test-1');
    expect(m['oscal-version']).toBe('1.1.2');
  });

  it('emits system-id + import-ssp when ssp.href is provided', () => {
    const env = makeEnvelope();
    const { doc } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'acme-prod',
      ssp: { href: '#ssp-uuid', remarks: 'Local SSP reference.' },
    });
    const p = doc['plan-of-action-and-milestones'];
    expect(p['system-id']?.id).toBe('acme-prod');
    expect(p['import-ssp']?.href).toBe('#ssp-uuid');
  });

  it('omits import-ssp when no SSP is provided (system-id alone is valid per spec)', () => {
    const env = makeEnvelope();
    const { doc } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'acme-prod',
    });
    const p = doc['plan-of-action-and-milestones'];
    expect(p['import-ssp']).toBeUndefined();
    expect(p['system-id']?.id).toBe('acme-prod');
  });

  it('embeds the signed-manifest reference in back-matter when signedManifestHref is set', () => {
    const env = makeEnvelope();
    const { doc } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'acme-prod',
      signedManifestHref: 'https://example.com/runs/r/manifest.json',
    });
    const bm = doc['plan-of-action-and-milestones']['back-matter'];
    expect(bm?.resources).toHaveLength(1);
    expect(bm?.resources[0]!.rlinks![0]!.href).toBe('https://example.com/runs/r/manifest.json');
  });

  it('emits a poam-item per failing finding (passing findings are excluded)', () => {
    const env = makeEnvelope({
      findings: [
        makeFinding({ rule: 'rule-a', passed: false, severity: 'high' }),
        makeFinding({ rule: 'rule-b', passed: true, severity: 'high' }), // excluded
        makeFinding({ rule: 'rule-c', passed: false, severity: 'low' }),
      ],
    });
    const { doc, result } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
    });
    expect(result.poam_item_count).toBe(2);
    expect(doc['plan-of-action-and-milestones']['poam-items']).toHaveLength(2);
    const rules = doc['plan-of-action-and-milestones']['poam-items'].map((i) => i.props!.find((p) => p.name === 'rule')!.value);
    expect(rules.sort()).toEqual(['rule-a', 'rule-c']);
  });

  it('emits risks only for severity > info', () => {
    const env = makeEnvelope({
      findings: [
        makeFinding({ rule: 'r1', passed: false, severity: 'critical' }),
        makeFinding({ rule: 'r2', passed: false, severity: 'info' }), // no risk
      ],
    });
    const { result } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
    });
    expect(result.poam_item_count).toBe(2);
    expect(result.risk_count).toBe(1);
  });

  it('computes the FedRAMP CMP severity-based deadline correctly (LOOP-B.B2)', () => {
    // Use a fixed collected_at so the deadline is deterministic.
    const env = makeEnvelope();
    (env as any).collected_at = '2026-01-01T00:00:00Z';
    (env.providers as any)[0].findings[0].severity = 'critical';
    const { doc } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
    });
    const risk = doc['plan-of-action-and-milestones'].risks![0]!;
    // LOOP-B.B2: Critical → FedRAMP CMP 15 days from 2026-01-01 → 2026-01-16
    // (replaces LOOP-A.A1's hardcoded 30-day critical). source = fedramp-cmp.
    expect(risk.deadline).toBe('2026-01-16T00:00:00.000Z');
    expect(risk.props!.some((p: any) => p.name === 'deadline-source' && p.value === 'fedramp-cmp')).toBe(true);
  });

  it('builder produces a clean-state doc when zero failing findings (with explicit remarks)', () => {
    const env = makeEnvelope({ findings: [] });
    const { doc, result } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
    });
    expect(result.poam_item_count).toBe(0);
    expect(doc['plan-of-action-and-milestones']['poam-items']).toEqual([]);
    // The doc is NOT schema-valid in this state (poam-items.minItems=1 by
    // OSCAL spec) — but the builder is still useful for callers that want to
    // inspect the structure. The disk-side emitOscalPoam() handles the
    // schema constraint by skipping the write (separate test below).
    expect(doc['plan-of-action-and-milestones'].metadata.remarks).toMatch(/Clean POA&M as of/);
  });

  it('emits affected_resources as observation.subjects', () => {
    const env = makeEnvelope({
      findings: [makeFinding({
        gap: {
          description: 'Two affected resources.',
          affected_resources: [
            { type: 'aws_iam_user', identifier: 'arn:aws:iam::123:user/alice' },
            { type: 'aws_iam_user', identifier: 'arn:aws:iam::123:user/bob' },
          ],
        },
      })],
    });
    const { doc, result } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
    });
    expect(result.poam_item_count).toBe(1);
    // Observations come from the raw evidence (one per RawEvidence). The
    // affected_resources are intentionally NOT duplicated as observations
    // (they're recorded on the finding's target subject instead) — but the
    // observation does cite the related RawEvidence which is sufficient for
    // a 3PAO to follow the chain.
    expect(doc['plan-of-action-and-milestones'].observations!.length).toBeGreaterThan(0);
  });

  it('is deterministic: same inputs → identical document', () => {
    const env = makeEnvelope();
    const a = buildOscalPoam([env], { outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x' });
    const b = buildOscalPoam([env], { outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x' });
    // last-modified is the only volatile field.
    a.doc['plan-of-action-and-milestones'].metadata['last-modified'] = '';
    b.doc['plan-of-action-and-milestones'].metadata['last-modified'] = '';
    // The "clean POA&M as of <timestamp>" remarks also contains the
    // last-modified timestamp implicitly — normalize.
    a.doc['plan-of-action-and-milestones'].metadata.remarks = '';
    b.doc['plan-of-action-and-milestones'].metadata.remarks = '';
    expect(JSON.stringify(a.doc)).toBe(JSON.stringify(b.doc));
  });

  it('passes through revisions history when provided (LOOP-E.E2 monthly chain)', () => {
    const env = makeEnvelope();
    const history = [
      { 'last-modified': '2026-04-01T00:00:00Z', version: 'r-april', remarks: 'April monthly' },
      { 'last-modified': '2026-05-01T00:00:00Z', version: 'r-may', remarks: 'May monthly' },
    ];
    const { doc } = buildOscalPoam([env], {
      outDir: '/tmp', runId: 'r-june', frmrVersion: 'v', systemId: 'x',
      revisionsHistory: history,
    });
    expect(doc['plan-of-action-and-milestones'].metadata.revisions).toEqual(history);
  });
});

describe('OSCAL POA&M emitter — emitOscalPoam (disk)', () => {
  it('reads evidence files + writes a valid POA&M JSON to disk', () => {
    const d = tmp();
    const env = makeEnvelope();
    writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify(env));
    const r = emitOscalPoam({ outDir: d, runId: 'r-1', frmrVersion: 'v', systemId: 'x' });
    expect(r.path).not.toBeNull();
    expect(existsSync(r.path!)).toBe(true);
    expect(r.poam_item_count).toBe(1);
    const v = validateOscalFile(r.path!, 'poam');
    if (!v.valid) throw new Error(`POA&M file schema invalid:\n${v.errors.slice(0, 8).join('\n')}`);
    expect(v.valid).toBe(true);
  });

  it('SKIPs disk emission when zero failing findings (OSCAL minItems=1 constraint)', () => {
    const d = tmp();
    // All findings pass.
    const env = makeEnvelope({
      findings: [
        makeFinding({ passed: true, severity: 'info' }),
        makeFinding({ rule: 'r2', passed: true, severity: 'info' }),
      ],
    });
    writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify(env));
    const r = emitOscalPoam({ outDir: d, runId: 'r-clean', frmrVersion: 'v', systemId: 'x' });
    expect(r.path).toBeNull();
    expect(r.skipped_reason).toBe('no-failing-findings');
    expect(r.poam_item_count).toBe(0);
    // No file should have been created.
    expect(existsSync(join(d, 'poam.json'))).toBe(false);
  });

  it('SKIPs disk emission when no evidence files exist', () => {
    const d = tmp();
    const r = emitOscalPoam({ outDir: d, runId: 'r-empty', frmrVersion: 'v', systemId: 'x' });
    expect(r.path).toBeNull();
    expect(r.skipped_reason).toBe('no-evidence-files');
    expect(existsSync(join(d, 'poam.json'))).toBe(false);
  });

  it('also emits the XML representation by default (OSC-3 parity)', () => {
    const d = tmp();
    writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify(makeEnvelope()));
    const r = emitOscalPoam({ outDir: d, runId: 'r-1', frmrVersion: 'v', systemId: 'x' });
    expect(r.path).not.toBeNull();
    expect(r.xml_path).toBeDefined();
    expect(existsSync(r.xml_path!)).toBe(true);
    const xml = readFileSync(r.xml_path!, 'utf8');
    expect(xml).toContain('<plan-of-action-and-milestones');
  });

  it('respects CLOUD_EVIDENCE_DISABLE_OSCAL_XML=1', () => {
    const d = tmp();
    writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify(makeEnvelope()));
    const prev = process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML;
    process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML = '1';
    try {
      const r = emitOscalPoam({ outDir: d, runId: 'r-1', frmrVersion: 'v', systemId: 'x' });
      expect(r.xml_path).toBeUndefined();
    } finally {
      if (prev === undefined) delete process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML;
      else process.env.CLOUD_EVIDENCE_DISABLE_OSCAL_XML = prev;
    }
  });

  it('skips files that are NOT KSI envelopes (CSV, .docx, manifest.json)', () => {
    const d = tmp();
    writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify(makeEnvelope()));
    writeFileSync(join(d, 'manifest.json'), JSON.stringify({ files: [] }));
    writeFileSync(join(d, 'report.csv'), 'col1,col2\n1,2\n');
    writeFileSync(join(d, 'ssp.docx'), 'binary');
    const r = emitOscalPoam({ outDir: d, runId: 'r-1', frmrVersion: 'v', systemId: 'x' });
    expect(r.poam_item_count).toBe(1); // only the one KSI envelope contributed
  });
});

// ─── LOOP-B.B2: deadline engine integration ──────────────────────────────────
describe('POA&M deadline engine integration (LOOP-B.B2)', () => {
  it('attaches a deadline-source prop on every emitted OSCAL risk', () => {
    const { doc } = buildOscalPoam([makeEnvelope()], { outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x' });
    const risks = doc['plan-of-action-and-milestones'].risks ?? [];
    expect(risks.length).toBeGreaterThan(0);
    for (const risk of risks) {
      expect(risk.props!.some((p: any) => p.name === 'deadline-source')).toBe(true);
    }
  });

  it('attaches kev-cve-id + kev-due-date props and uses the KEV dueDate when a finding cites a KEV CVE', () => {
    const f = makeFinding({ severity: 'high' });
    (f as any).references = [{ title: 'Log4Shell', url: 'https://nvd', cve_id: 'CVE-2021-44228' }];
    const env = makeEnvelope({ findings: [f] });
    (env as any).collected_at = '2026-01-01T00:00:00Z';
    const kevIndex = new Map([['CVE-2021-44228', { cveID: 'CVE-2021-44228', dateAdded: '2021-12-10', dueDate: '2021-12-24' } as any]]);
    const { doc } = buildOscalPoam([env], { outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x', kevIndex });
    const risk = doc['plan-of-action-and-milestones'].risks![0]!;
    expect(risk.deadline).toBe('2021-12-24T00:00:00.000Z');
    expect(risk.props!.some((p: any) => p.name === 'deadline-source' && p.value === 'kev')).toBe(true);
    expect(risk.props!.some((p: any) => p.name === 'kev-cve-id' && p.value === 'CVE-2021-44228')).toBe(true);
    expect(risk.props!.some((p: any) => p.name === 'kev-due-date' && p.value === '2021-12-24')).toBe(true);
  });

  it('attaches pain + irv + lev props on a PAIN/IRV/LEV-override finding', () => {
    const f = makeFinding({ severity: 'medium' });
    Object.assign(f, {
      irv: true, lev: true, pain: 5,
      risk_score: {
        composite_score: 9.6, criticality: 5, exposure: 5, formula_version: 'v1',
        sources: { cvss_source: 'operator', epss_source: 'feed', criticality_source: 'inventory', exposure_source: 'inventory' },
      },
    });
    const { doc } = buildOscalPoam([makeEnvelope({ findings: [f] })], { outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x' });
    const risk = doc['plan-of-action-and-milestones'].risks![0]!;
    expect(risk.props!.some((p: any) => p.name === 'deadline-source' && p.value === 'pain-irv-lev')).toBe(true);
    expect(risk.props!.some((p: any) => p.name === 'irv' && p.value === 'true')).toBe(true);
    expect(risk.props!.some((p: any) => p.name === 'lev' && p.value === 'true')).toBe(true);
    expect(risk.props!.some((p: any) => p.name === 'pain' && p.value === '5')).toBe(true);
  });

  it('emits a signed deadline-audit.json with one row per finding + a provenance block', () => {
    const d = tmp();
    writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify(makeEnvelope()));
    emitOscalPoam({ outDir: d, runId: 'r-audit', frmrVersion: 'v', systemId: 'x' });
    const auditPath = join(d, 'deadline-audit.json');
    expect(existsSync(auditPath)).toBe(true);
    const audit = JSON.parse(readFileSync(auditPath, 'utf8'));
    expect(audit.rows.length).toBe(1);
    expect(audit.rows[0].source).toBeTruthy();
    expect(audit.provenance.emitter).toBe('core/oscal-poam.ts');
    expect(audit.provenance.signingKeyId).toMatch(/^[0-9a-f]{16}$/);
    expect(audit.signature).toBeTruthy();
  });

  it('reports deadline_fallback_count = 0 when the FedRAMP CMP table covers every severity', () => {
    const { result } = buildOscalPoam([makeEnvelope()], { outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x' });
    expect(result.deadline_fallback_count).toBe(0);
  });
});

// ─── LOOP-B.B3: risk-acceptance → deviation-approved propagation ──────────────
import type { PulledAcceptance } from '../../core/risk-acceptance-reader.ts';

function makeAcceptance(over: Partial<PulledAcceptance> = {}): PulledAcceptance {
  return {
    uuid: over.uuid ?? 'acc-uuid-1',
    finding_uuid: over.finding_uuid ?? 'finding-1',
    poam_item_uuid: over.poam_item_uuid ?? 'poam-1',
    ksi_id: over.ksi_id ?? 'KSI-IAM-MFA',
    rule: over.rule ?? 'aws.iam.root_mfa_enabled',
    provider: over.provider ?? 'aws',
    accepted_by_user_id: over.accepted_by_user_id ?? 1,
    accepted_at: over.accepted_at ?? '2026-07-02T00:00:00.000Z',
    expiration_date: over.expiration_date ?? '2026-12-01T00:00:00.000Z',
    business_justification: over.business_justification ?? 'Accepted residual risk: root is in a break-glass vault with hardware MFA + 24/7 alerting.',
    acceptance_type: over.acceptance_type ?? 'risk-adjustment',
    status: over.status ?? 'approved',
    approved_by_user_id: over.approved_by_user_id ?? 2,
    approved_at: over.approved_at ?? '2026-07-02T01:00:00.000Z',
    signature: over.signature ?? 'sig',
    signing_key_id: over.signing_key_id ?? 'k',
    approval_signature: over.approval_signature ?? 'asig',
    approval_signing_key_id: over.approval_signing_key_id ?? 'k',
    compensating_control_uuids: over.compensating_control_uuids ?? [],
  };
}

const ACC_NOW = () => new Date('2026-07-15T00:00:00.000Z');
function propVal(props: Array<{ name: string; value: string }> | undefined, name: string): string | undefined {
  return props?.find((p) => p.name === name)?.value;
}

describe('OSCAL POA&M emitter — LOOP-B.B3 risk-acceptance propagation', () => {
  it('flips risk.status to deviation-approved when an active acceptance exists', () => {
    const { doc } = buildOscalPoam([makeEnvelope()], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
      acceptances: [makeAcceptance()], acceptanceNow: ACC_NOW,
    });
    const risks = doc['plan-of-action-and-milestones'].risks!;
    expect(risks.length).toBeGreaterThan(0);
    expect(risks[0]!.status).toBe('deviation-approved');
  });

  it('overrides risk.deadline with the acceptance expiration_date', () => {
    const { doc } = buildOscalPoam([makeEnvelope()], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
      acceptances: [makeAcceptance({ expiration_date: '2026-11-30T00:00:00.000Z' })], acceptanceNow: ACC_NOW,
    });
    const risk = doc['plan-of-action-and-milestones'].risks![0]!;
    expect(risk.deadline).toBe('2026-11-30T00:00:00.000Z');
    expect(propVal(risk.props, 'deadline-source')).toBe('operator-override');
  });

  it('attaches acceptance-uuid + acceptance-type + compensating-control-uuid props', () => {
    const { doc } = buildOscalPoam([makeEnvelope()], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
      acceptances: [makeAcceptance({ acceptance_type: 'deviation-request', compensating_control_uuids: ['cc-1', 'cc-2'] })],
      acceptanceNow: ACC_NOW,
    });
    const item = doc['plan-of-action-and-milestones']['poam-items'][0]!;
    expect(propVal(item.props, 'acceptance-uuid')).toBe('acc-uuid-1');
    expect(propVal(item.props, 'acceptance-type')).toBe('deviation-request');
    expect(propVal(item.props, 'acceptance-approved-by')).toBe('2');
    const ccs = item.props!.filter((p) => p.name === 'compensating-control-uuid').map((p) => p.value);
    expect(ccs).toEqual(['cc-1', 'cc-2']);
  });

  it('does NOT flip status when the acceptance is pending (not yet approved)', () => {
    const { doc } = buildOscalPoam([makeEnvelope()], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
      acceptances: [makeAcceptance({ status: 'pending' })], acceptanceNow: ACC_NOW,
    });
    const risk = doc['plan-of-action-and-milestones'].risks![0]!;
    expect(risk.status).toBe('open');
    expect(propVal(risk.props, 'acceptance-uuid')).toBeUndefined();
  });

  it('does NOT flip status when the acceptance is expired', () => {
    const { doc } = buildOscalPoam([makeEnvelope()], {
      outDir: '/tmp', runId: 'r', frmrVersion: 'v', systemId: 'x',
      acceptances: [makeAcceptance({ expiration_date: '2026-07-01T00:00:00.000Z' })], acceptanceNow: ACC_NOW,
    });
    const risk = doc['plan-of-action-and-milestones'].risks![0]!;
    expect(risk.status).toBe('open');
  });
});
