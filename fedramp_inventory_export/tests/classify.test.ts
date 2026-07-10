import { describe, it, expect } from 'vitest';
import { classifyRequirement } from '../src/classify.ts';

describe('classifyRequirement', () => {
  it('classifies a CLOUD-scope KSI as automated with no artifact owed', () => {
    const c = classifyRequirement({ ksi_id: 'KSI-CNA-MAT', family: 'CNA', scope: 'CLOUD' });
    expect(c.assessmentType).toBe('automated');
    expect(c.artifactOwed).toBe('');
    expect(c.label).toMatch(/Automated/);
  });

  it('classifies a HYBRID-scope KSI as hybrid with a named artifact', () => {
    const c = classifyRequirement({ ksi_id: 'KSI-RPL-TRC', family: 'RPL', scope: 'HYBRID' });
    expect(c.assessmentType).toBe('hybrid');
    expect(c.artifactOwed).toMatch(/restore test|recovery/i);
  });

  it('classifies a PROCESS-scope KSI as documentation with its FedRAMP artifact', () => {
    const c = classifyRequirement({ ksi_id: 'KSI-AFR-SCG', family: 'AFR', scope: 'PROCESS' });
    expect(c.assessmentType).toBe('documentation');
    expect(c.artifactOwed).toMatch(/Secure Configuration Guide/);
  });

  it('classifies awareness-only / non-provider actor as external', () => {
    const c = classifyRequirement({ ksi_id: 'VDR-FRP-CAP', family: 'VDR', scope: 'PROCESS', awareness_only: true });
    expect(c.assessmentType).toBe('external');
  });

  it('falls back to a family hint when no explicit artifact exists', () => {
    const c = classifyRequirement({ ksi_id: 'KSI-CED-XYZ', family: 'CED', scope: 'PROCESS' });
    expect(c.assessmentType).toBe('documentation');
    expect(c.artifactOwed).toMatch(/[Tt]raining/);
  });
});
