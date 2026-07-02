/**
 * LOOP-B.B5 — Central Risk Register aggregator tests.
 *
 * Covers the per-slice doc §8 aggregator specs (1-11): finding/acceptance/
 * organisational source entries, EPSS→likelihood + criticality→impact band
 * derivation, the NIST 800-30 Table I-2 inherent matrix, residual reduction by
 * compensating controls + treatment, acceptance-preferred de-dup, the
 * REQUIRES-OPERATOR-INPUT propagation, and the signed provenance emit.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import {
  buildRiskRegister,
  emitRiskRegister,
  combineInherent,
  likelihoodFromEpssPercentile,
  impactFromCriticality,
  deriveResidual,
  dropBands,
  summarise,
  REQUIRES_OPERATOR_INPUT,
  type BuildInputs,
} from '../../core/risk-register.ts';
import type { PulledAcceptance } from '../../core/risk-acceptance-reader.ts';
import type { PulledCompensatingControl } from '../../core/compensating-control-reader.ts';
import type { PulledOrganisationalRisk } from '../../core/organisational-risk-reader.ts';

const NOW = new Date('2026-07-02T12:00:00.000Z');
const FUTURE = '2026-12-31T00:00:00.000Z';

interface RiskProp { name: string; value: string }
function riskProps(over: Record<string, string | string[]> = {}): RiskProp[] {
  const base: Record<string, string | string[]> = {
    'epss-percentile': '0.960',
    'criticality': '0.95',
    'risk-score-source-epss': 'api',
    'risk-score-source-criticality': 'data-classification',
    'cvss-base': '9.8',
    'epss-score': '0.80000',
    'nist-control': ['ra-5'],
    ...over,
  };
  const props: RiskProp[] = [];
  for (const [name, v] of Object.entries(base)) {
    if (Array.isArray(v)) for (const x of v) props.push({ name, value: x });
    else props.push({ name, value: v });
  }
  return props;
}

function mkRisk(uuid: string, over: Partial<{ status: string; deadline: string; props: RiskProp[]; title: string; description: string }> = {}) {
  return {
    uuid,
    title: over.title ?? `KSI-IAM-MFA / ${uuid}`,
    description: over.description ?? 'MFA not enforced on root',
    status: over.status ?? 'open',
    deadline: over.deadline ?? FUTURE,
    props: over.props ?? riskProps(),
  };
}

function inputs(over: Partial<BuildInputs> = {}): BuildInputs {
  return {
    risks: [],
    poamItemByRisk: new Map(),
    acceptances: [],
    compensatingControls: [],
    organisationalRisks: [],
    now: NOW,
    ...over,
  };
}

function mkAcceptance(over: Partial<PulledAcceptance> = {}): PulledAcceptance {
  return {
    uuid: 'acc-1', finding_uuid: 'f-1', poam_item_uuid: 'pi-1', ksi_id: 'KSI-IAM-MFA', rule: 'iam-mfa-aws-root',
    provider: 'aws', accepted_by_user_id: 1, accepted_at: '2026-06-01T00:00:00.000Z', expiration_date: FUTURE,
    business_justification: 'x'.repeat(120), acceptance_type: 'risk-adjustment', status: 'approved',
    approved_by_user_id: 2, approved_at: '2026-06-02T00:00:00.000Z', signature: 's', signing_key_id: 'k',
    approval_signature: 'as', approval_signing_key_id: 'ak', compensating_control_uuids: [], ...over,
  };
}

function mkCc(over: Partial<PulledCompensatingControl> = {}): PulledCompensatingControl {
  return {
    uuid: 'cc-1', title: 'MFA vault', description: 'x'.repeat(220), nist_control_ids: ['ac-2'],
    implemented_by_user_id: 1, implemented_at: '2026-06-01T00:00:00.000Z', signed_off_by_user_id: 2,
    signed_off_at: '2026-06-02T00:00:00.000Z', expiration_date: null, evidence_url: null, evidence_sha256: null,
    status: 'active', signature: 's', signing_key_id: 'k', ...over,
  };
}

function mkOrg(over: Partial<PulledOrganisationalRisk> = {}): PulledOrganisationalRisk {
  return {
    uuid: 'org-1', title: 'Key vendor bankruptcy', description: 'x'.repeat(120), category: 'third-party',
    likelihood: 'moderate', impact: 'high', inherent_risk: 'moderate', residual_risk: 'low', treatment: 'transfer',
    owner: 'CISO', review_date: FUTURE, nist_control_ids: ['sa-9'], compensating_control_uuids: null,
    status: 'open', closed_at: null, created_at: '2026-06-01T00:00:00.000Z', updated_at: '2026-06-01T00:00:00.000Z', ...over,
  };
}

describe('buildRiskRegister — finding entries', () => {
  it('aggregates per-finding risks from POA&M into source=finding entries', () => {
    const entries = buildRiskRegister(inputs({
      risks: [mkRisk('r-1')],
      poamItemByRisk: new Map([['r-1', 'pi-1']]),
    }));
    expect(entries).toHaveLength(1);
    expect(entries[0].source).toBe('finding');
    expect(entries[0].uuid).toBe('r-1');
    expect(entries[0].references.risk_uuid).toBe('r-1');
    expect(entries[0].references.poam_item_uuid).toBe('pi-1');
    expect(entries[0].references.nist_control_ids).toEqual(['ra-5']);
    expect(entries[0].category).toBe('ksi-finding');
  });

  it('skips closed risks (Q3: remediated findings drop off)', () => {
    const entries = buildRiskRegister(inputs({ risks: [mkRisk('r-1', { status: 'closed' })] }));
    expect(entries).toHaveLength(0);
  });

  it('derives likelihood from EPSS percentile bands per documented table', () => {
    expect(likelihoodFromEpssPercentile(0.96)).toBe('very-high');
    expect(likelihoodFromEpssPercentile(0.6)).toBe('high');
    expect(likelihoodFromEpssPercentile(0.1)).toBe('moderate');
    expect(likelihoodFromEpssPercentile(0.01)).toBe('low');
    expect(likelihoodFromEpssPercentile(0.001)).toBe('very-low');
    const e = buildRiskRegister(inputs({ risks: [mkRisk('r-1', { props: riskProps({ 'epss-percentile': '0.60' }) })] }));
    expect(e[0].likelihood).toBe('high');
  });

  it('derives impact from criticality bands per documented table', () => {
    expect(impactFromCriticality(0.95)).toBe('very-high');
    expect(impactFromCriticality(0.75)).toBe('high');
    expect(impactFromCriticality(0.5)).toBe('moderate');
    expect(impactFromCriticality(0.25)).toBe('low');
    expect(impactFromCriticality(0.1)).toBe('very-low');
    const e = buildRiskRegister(inputs({ risks: [mkRisk('r-1', { props: riskProps({ 'criticality': '0.75' }) })] }));
    expect(e[0].impact).toBe('high');
  });

  it('combines likelihood × impact per NIST 800-30 Table I-2 matrix', () => {
    // Worked example: very-high likelihood × very-high impact = very-high.
    expect(combineInherent('very-high', 'very-high')).toBe('very-high');
    // moderate × high = moderate (row Moderate, col High per Table I-2).
    expect(combineInherent('moderate', 'high')).toBe('moderate');
    // low × very-high = moderate; very-low × very-low = very-low.
    expect(combineInherent('low', 'very-high')).toBe('moderate');
    expect(combineInherent('very-low', 'very-low')).toBe('very-low');
    const e = buildRiskRegister(inputs({ risks: [mkRisk('r-1')] }));
    expect(e[0].inherent_risk).toBe('very-high');
  });
});

describe('buildRiskRegister — residual reduction', () => {
  it('drops residual_risk one band when an active compensating control is linked', () => {
    expect(dropBands('very-high', 1)).toBe('high');
    // Finding whose props cite a CC uuid resolving to an active control.
    const risk = mkRisk('r-1', { props: riskProps({ 'compensating-control-uuid': ['cc-1'] }) });
    const e = buildRiskRegister(inputs({
      risks: [risk],
      compensatingControls: [mkCc({ uuid: 'cc-1' })],
    }));
    expect(e[0].inherent_risk).toBe('very-high');
    expect(e[0].residual_risk).toBe('high');
  });

  it('drops two bands for treatment=transfer or treatment=avoid', () => {
    expect(deriveResidual('very-high', 'transfer', 0)).toBe('moderate');
    expect(deriveResidual('very-high', 'avoid', 0)).toBe('moderate');
    // Organisational entry with treatment=transfer keeps its verbatim residual.
    const e = buildRiskRegister(inputs({ organisationalRisks: [mkOrg({ treatment: 'transfer', residual_risk: 'low' })] }));
    expect(e[0].treatment).toBe('transfer');
    expect(e[0].residual_risk).toBe('low');
  });
});

describe('buildRiskRegister — acceptance entries + de-dup', () => {
  it('aggregates active acceptances as source=acceptance entries with treatment=accept', () => {
    const e = buildRiskRegister(inputs({ acceptances: [mkAcceptance()] }));
    expect(e).toHaveLength(1);
    expect(e[0].source).toBe('acceptance');
    expect(e[0].treatment).toBe('accept');
    expect(e[0].references.acceptance_uuid).toBe('acc-1');
    expect(e[0].owner).toBe('AO');
  });

  it('de-duplicates: acceptance entry preferred over finding entry for same poam_item', () => {
    const risk = mkRisk('r-1', { status: 'deviation-approved' });
    const e = buildRiskRegister(inputs({
      risks: [risk],
      poamItemByRisk: new Map([['r-1', 'pi-1']]),
      acceptances: [mkAcceptance({ poam_item_uuid: 'pi-1' })],
    }));
    // Only the acceptance entry survives for pi-1; the finding entry is suppressed.
    expect(e.filter((x) => x.source === 'finding')).toHaveLength(0);
    expect(e.filter((x) => x.source === 'acceptance')).toHaveLength(1);
    // The acceptance inherits the finding's bands via the poam_item join.
    expect(e[0].inherent_risk).toBe('very-high');
  });
});

describe('buildRiskRegister — organisational entries + markers', () => {
  it('aggregates organisational risks verbatim from snapshot', () => {
    const e = buildRiskRegister(inputs({ organisationalRisks: [mkOrg()] }));
    expect(e).toHaveLength(1);
    expect(e[0].source).toBe('organisational');
    expect(e[0].category).toBe('third-party');
    expect(e[0].likelihood).toBe('moderate');
    expect(e[0].inherent_risk).toBe('moderate');
    expect(e[0].residual_risk).toBe('low');
    expect(e[0].references.organisational_risk_uuid).toBe('org-1');
  });

  it('emits REQUIRES-OPERATOR-INPUT marker when underlying B.B1 source marker present', () => {
    const risk = mkRisk('r-1', { props: riskProps({ 'risk-score-source-epss': REQUIRES_OPERATOR_INPUT }) });
    const e = buildRiskRegister(inputs({ risks: [risk] }));
    expect(e[0].likelihood).toBe(REQUIRES_OPERATOR_INPUT);
    expect(e[0].inherent_risk).toBe(REQUIRES_OPERATOR_INPUT);
    expect(e[0].residual_risk).toBe(REQUIRES_OPERATOR_INPUT);
  });
});

describe('emitRiskRegister', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(resolve(tmpdir(), 'rr-')); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  function writePoam(risks: any[], items: any[] = []): void {
    writeFileSync(resolve(dir, 'poam.json'), JSON.stringify({
      'plan-of-action-and-milestones': { uuid: 'p', risks, 'poam-items': items },
    }));
  }

  it('emits risk-register.json with provenance.emitter + sourceCalls + summary block', () => {
    writePoam([mkRisk('r-1')], [{ uuid: 'pi-1', 'related-risks': [{ 'risk-uuid': 'r-1' }] }]);
    const res = emitRiskRegister({ outDir: dir, runId: 'run-1', now: () => NOW });
    expect(existsSync(res.jsonPath)).toBe(true);
    expect(existsSync(res.xlsxPath)).toBe(true);
    const doc = JSON.parse(readFileSync(res.jsonPath, 'utf8'));
    expect(doc.provenance.emitter).toBe('core/risk-register.ts');
    expect(doc.provenance.sourceCalls.length).toBeGreaterThanOrEqual(4);
    expect(doc.provenance.signingKeyId).toBeTruthy();
    expect(doc.signature.algorithm).toBe('ed25519');
    expect(doc.summary.entries_total).toBe(1);
    expect(doc.summary.by_source.finding).toBe(1);
    expect(doc.entries[0].references.poam_item_uuid).toBe('pi-1');
  });

  it('summarise counts open + high-inherent entries', () => {
    const s = summarise(buildRiskRegister(inputs({ risks: [mkRisk('r-1'), mkRisk('r-2', { props: riskProps({ 'epss-percentile': '0.001', 'criticality': '0.1' }) })] })));
    expect(s.entries_total).toBe(2);
    expect(s.high_inherent_count).toBe(1); // only r-1 is very-high
    expect(s.open_count).toBe(2);
  });
});
