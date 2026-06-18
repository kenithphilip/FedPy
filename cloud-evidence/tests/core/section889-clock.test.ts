/**
 * Tests for the LOOP-W.W3 federal-business-day clock (core/section889-clock.ts).
 *
 * Covers W.W3 §8 T1–T4 (next-business-day / weekend-skip / holiday rollover /
 * back-to-back-holiday rollover), T19 (DST transition), plus the OPM in-lieu-of
 * observed-holiday rule, operator agency closures, and the elapsed/remaining
 * helpers. Deadlines are compared as absolute instants (ET wall-clock and UTC
 * denote the same instant), so the assertions are timezone-offset agnostic.
 */
import { describe, it, expect } from 'vitest';
import {
  deadlineFor, followUpDeadlineFor, addFederalBusinessHours,
  federalBusinessHoursBetween, businessHoursRemaining, isFederalBusinessDate,
} from '../../core/section889-clock.ts';

/** Wall-clock {hour,day,month,year} of an instant in America/New_York. */
function etWall(iso: string) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York', hourCycle: 'h23',
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).formatToParts(new Date(iso));
  const m: Record<string, string> = {};
  for (const p of parts) if (p.type !== 'literal') m[p.type] = p.value;
  return { year: +m.year, month: +m.month, day: +m.day, hour: +m.hour % 24, minute: +m.minute };
}
const sameInstant = (a: string, b: string) => expect(new Date(a).getTime()).toBe(new Date(b).getTime());

describe('section889-clock — 1-business-day deadline', () => {
  it('T1: Wed 10:00 ET → deadline Thu 10:00 ET (no holidays)', () => {
    sameInstant(deadlineFor('2026-06-10T10:00:00-04:00'), '2026-06-11T10:00:00-04:00');
  });

  it('T2: Fri 16:00 ET → deadline Mon 16:00 ET (weekend skipped, 7h carry)', () => {
    sameInstant(deadlineFor('2026-06-12T16:00:00-04:00'), '2026-06-15T16:00:00-04:00');
  });

  it('T3: Christmas Eve 14:00 ET → rolls past Fri Christmas + weekend to Mon Dec 28 14:00 ET', () => {
    sameInstant(deadlineFor('2026-12-24T14:00:00-05:00'), '2026-12-28T14:00:00-05:00');
  });

  it('T4: New Year\'s Eve 14:00 ET → rolls past Fri Jan 1 2027 holiday + weekend to Mon Jan 4 14:00 ET', () => {
    sameInstant(deadlineFor('2026-12-31T14:00:00-05:00'), '2027-01-04T14:00:00-05:00');
  });

  it('T19: DST spring-forward Sun Mar 8 2026 16:30 ET → Mon Mar 9 17:00 EDT, no off-by-one hour', () => {
    const deadline = deadlineFor('2026-03-08T16:30:00-05:00'); // Sunday before clocks spring forward
    sameInstant(deadline, '2026-03-09T17:00:00-04:00');
    const w = etWall(deadline);
    expect(w.hour).toBe(17); // exactly close-of-business, not 16:00 or 18:00
    expect(w.month).toBe(3);
    expect(w.day).toBe(9);
  });

  it('discovery before 09:00 ET starts the clock at open (08:00 → +8h → 17:00 same day)', () => {
    sameInstant(deadlineFor('2026-06-10T08:00:00-04:00'), '2026-06-10T17:00:00-04:00');
  });

  it('discovery exactly at 09:00 ET → +8h → 17:00 same day', () => {
    sameInstant(deadlineFor('2026-06-10T09:00:00-04:00'), '2026-06-10T17:00:00-04:00');
  });

  it('discovery after close (18:00 Fri) starts Monday open → Mon 17:00', () => {
    sameInstant(deadlineFor('2026-06-12T18:00:00-04:00'), '2026-06-15T17:00:00-04:00');
  });

  it('discovery on a federal holiday rolls to the next business day', () => {
    // Juneteenth 2026 is Fri Jun 19; clock starts Mon Jun 22 09:00 → +8h → 17:00.
    sameInstant(deadlineFor('2026-06-19T10:00:00-04:00'), '2026-06-22T17:00:00-04:00');
  });
});

describe('section889-clock — federal-holiday calendar (5 U.S.C. §6103 + OPM in-lieu-of)', () => {
  it('Christmas Day (Dec 25 2026, a Friday) is not a business date', () => {
    expect(isFederalBusinessDate(2026, 12, 25)).toBe(false);
  });
  it('in-lieu-of: July 4 2026 falls on Saturday → observed Friday Jul 3 is not a business date', () => {
    // bizdays observes Sat holidays on the preceding Friday.
    expect(isFederalBusinessDate(2026, 7, 3)).toBe(false);
  });
  it('a normal weekday is a business date', () => {
    expect(isFederalBusinessDate(2026, 6, 10)).toBe(true);
  });
  it('Saturday / Sunday are not business dates', () => {
    expect(isFederalBusinessDate(2026, 6, 13)).toBe(false);
    expect(isFederalBusinessDate(2026, 6, 14)).toBe(false);
  });
});

describe('section889-clock — operator agency closures', () => {
  it('an operator closure day is skipped like a holiday', () => {
    const opts = { extraClosures: ['2026-06-11'] }; // close the Thursday after a Wed discovery
    // Wed 10:00 +8h would be Thu 10:00, but Thu is closed → rolls to Fri 10:00.
    sameInstant(deadlineFor('2026-06-10T10:00:00-04:00', opts), '2026-06-12T10:00:00-04:00');
    expect(isFederalBusinessDate(2026, 6, 11, opts)).toBe(false);
  });
});

describe('section889-clock — 10-business-day follow-up', () => {
  it('follow-up deadline is 10 federal business days after the anchor', () => {
    // Wed 2026-06-10 10:00 ET + 10 business days (skipping Juneteenth Fri Jun 19) → Thu Jun 25 10:00 ET.
    sameInstant(followUpDeadlineFor('2026-06-10T10:00:00-04:00'), '2026-06-25T10:00:00-04:00');
  });
});

describe('section889-clock — elapsed + remaining helpers', () => {
  it('federalBusinessHoursBetween counts only business hours', () => {
    // Wed 10:00 → Thu 10:00 ET is exactly one business day = 8 business hours.
    expect(federalBusinessHoursBetween('2026-06-10T10:00:00-04:00', '2026-06-11T10:00:00-04:00')).toBeCloseTo(8, 3);
  });
  it('businessHoursRemaining is 0 once the deadline has passed', () => {
    expect(businessHoursRemaining('2026-06-12T10:00:00-04:00', '2026-06-11T10:00:00-04:00')).toBe(0);
  });
  it('businessHoursRemaining equals the budget at the moment of discovery', () => {
    const disc = '2026-06-10T10:00:00-04:00';
    const dl = deadlineFor(disc);
    expect(businessHoursRemaining(disc, dl)).toBeCloseTo(8, 3);
  });
  it('addFederalBusinessHours with 0 hours clamps to the next business-hour boundary', () => {
    // Saturday → next business open Monday 09:00.
    sameInstant(addFederalBusinessHours('2026-06-13T12:00:00-04:00', 0), '2026-06-15T09:00:00-04:00');
  });
});
