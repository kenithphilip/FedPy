import { describe, it, expect } from 'vitest';
import { COLUMN_META, STATUS_RISK, columnWidth } from '../src/columns.ts';

describe('inventory risk predicates', () => {
  it('flags the specific risky value per control column', () => {
    expect(COLUMN_META['Encryption At Rest']!.risk!.when('No')).toBe(true);
    expect(COLUMN_META['Encryption At Rest']!.risk!.when('Yes')).toBe(false);
    expect(COLUMN_META['Public Facing']!.risk!.when('Yes')).toBe(true);
    expect(COLUMN_META['MFA Enabled']!.risk!.when('No')).toBe(true);
    expect(COLUMN_META['Access Key Age (days)']!.risk!.when('120')).toBe(true);
    expect(COLUMN_META['Access Key Age (days)']!.risk!.when('30')).toBe(false);
    expect(COLUMN_META['Missing Required Tags']!.risk!.when('Owner; Environment')).toBe(true);
    expect(COLUMN_META['Missing Required Tags']!.risk!.when('')).toBe(false);
    expect(COLUMN_META['Patch Level']!.risk!.when('3 missing (10 installed)')).toBe(true);
    expect(COLUMN_META['Patch Level']!.risk!.when('Current (42 installed)')).toBe(false);
  });

  it('identity/metadata columns carry no risk rule', () => {
    expect(COLUMN_META['Unique Asset Identifier']!.risk).toBeUndefined();
    expect(COLUMN_META['Location']!.risk).toBeUndefined();
  });

  it('status columns map words to tones', () => {
    expect(STATUS_RISK['Compliance Status']!('non-compliant')).toBe('red');
    expect(STATUS_RISK['Compliance Status']!('compliant')).toBe('good');
    expect(STATUS_RISK['Compliance Status']!('not-assessed')).toBe('grey');
    expect(STATUS_RISK['Severity']!('critical')).toBe('red');
    expect(STATUS_RISK['Severity']!('medium')).toBe('amber');
    expect(STATUS_RISK['Priority']!('P1 - Critical')).toBe('red');
  });

  it('gives ARNs/detail columns generous width', () => {
    expect(columnWidth('Unique Asset Identifier')).toBeGreaterThanOrEqual(50);
    expect(columnWidth('vCPU')).toBeLessThanOrEqual(10);
  });
});
