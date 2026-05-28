/**
 * Business-day + deadline arithmetic for FedRAMP cadence / SLA requirements.
 *
 * Many FRR requirements impose deadlines in *business days* (e.g. "report by
 * 3pm ET on the 2nd business day") or calendar windows (e.g. KEV due dates,
 * "within 24 hours", quarterly reviews). The VDR / CCM / SCN / FSI / ICP
 * trackers all need consistent, testable date math so a missed deadline is a
 * deterministic finding rather than a judgment call.
 *
 * US federal holidays are included because FedRAMP deadlines reference federal
 * business days. The list is computed (not hard-coded per year) so it stays
 * correct across years without maintenance.
 *
 * Pure functions, no side effects, no I/O.
 */

const DAY_MS = 86_400_000;

function isWeekend(d: Date): boolean {
  const day = d.getUTCDay();
  return day === 0 || day === 6; // Sun / Sat
}

/** Nth weekday-of-month, e.g. nthWeekday(2026, 0, 1, 3) = 3rd Monday of January 2026. */
function nthWeekday(year: number, month0: number, weekday: number, n: number): Date {
  const first = new Date(Date.UTC(year, month0, 1));
  const offset = (7 + weekday - first.getUTCDay()) % 7;
  return new Date(Date.UTC(year, month0, 1 + offset + (n - 1) * 7));
}

/** Last weekday-of-month (e.g. last Monday = Memorial Day). */
function lastWeekday(year: number, month0: number, weekday: number): Date {
  const last = new Date(Date.UTC(year, month0 + 1, 0));
  const offset = (7 + last.getUTCDay() - weekday) % 7;
  return new Date(Date.UTC(year, month0 + 1, 0 - offset));
}

function observed(d: Date): Date {
  // Federal holidays falling on Sat are observed Fri; on Sun observed Mon.
  const day = d.getUTCDay();
  if (day === 6) return new Date(d.getTime() - DAY_MS);
  if (day === 0) return new Date(d.getTime() + DAY_MS);
  return d;
}

/** US federal holidays (observed) for a given year, as YYYY-MM-DD strings. */
export function usFederalHolidays(year: number): Set<string> {
  const ymd = (d: Date) => d.toISOString().slice(0, 10);
  const fixed = [
    new Date(Date.UTC(year, 0, 1)), // New Year's Day
    new Date(Date.UTC(year, 5, 19)), // Juneteenth
    new Date(Date.UTC(year, 6, 4)), // Independence Day
    new Date(Date.UTC(year, 10, 11)), // Veterans Day
    new Date(Date.UTC(year, 11, 25)), // Christmas
  ].map(observed);
  const floating = [
    nthWeekday(year, 0, 1, 3), // MLK — 3rd Mon Jan
    nthWeekday(year, 1, 1, 3), // Washington's Birthday — 3rd Mon Feb
    lastWeekday(year, 4, 1), // Memorial Day — last Mon May
    nthWeekday(year, 8, 1, 1), // Labor Day — 1st Mon Sep
    nthWeekday(year, 9, 1, 2), // Columbus Day — 2nd Mon Oct
    nthWeekday(year, 10, 4, 4), // Thanksgiving — 4th Thu Nov
  ];
  return new Set([...fixed, ...floating].map(ymd));
}

const _holidayCache = new Map<number, Set<string>>();
function holidaysFor(year: number): Set<string> {
  let s = _holidayCache.get(year);
  if (!s) { s = usFederalHolidays(year); _holidayCache.set(year, s); }
  return s;
}

/** Is `d` a US federal business day (not weekend, not a federal holiday)? */
export function isBusinessDay(d: Date): boolean {
  if (isWeekend(d)) return false;
  return !holidaysFor(d.getUTCFullYear()).has(d.toISOString().slice(0, 10));
}

/** Add `n` business days to `start` (n may be 0). */
export function addBusinessDays(start: Date, n: number): Date {
  let d = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()));
  let remaining = n;
  const step = n >= 0 ? 1 : -1;
  while (remaining !== 0) {
    d = new Date(d.getTime() + step * DAY_MS);
    if (isBusinessDay(d)) remaining -= step;
  }
  return d;
}

/** Count business days between two dates (exclusive of start, inclusive of end). */
export function businessDaysBetween(a: Date, b: Date): number {
  const [start, end] = a <= b ? [a, b] : [b, a];
  let d = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()));
  const endUtc = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate()));
  let count = 0;
  while (d < endUtc) {
    d = new Date(d.getTime() + DAY_MS);
    if (isBusinessDay(d)) count++;
  }
  return a <= b ? count : -count;
}

/** Calendar days between two dates (b - a), floored. */
export function calendarDaysBetween(a: Date, b: Date): number {
  return Math.floor((b.getTime() - a.getTime()) / DAY_MS);
}

export interface DeadlineStatus {
  due: string;            // ISO date the obligation is due
  now: string;            // ISO now
  overdue: boolean;
  /** Negative = days remaining; positive = days overdue. */
  days_past_due: number;
  basis: 'business-days' | 'calendar-days';
}

/**
 * Compute deadline status from an anchor event + an allowed window.
 *
 *   deadlineStatus('2026-05-01T00:00Z', { businessDays: 2 })
 *   deadlineStatus('2026-05-01T00:00Z', { calendarDays: 14 })
 */
export function deadlineStatus(
  anchorIso: string,
  window: { businessDays?: number; calendarDays?: number },
  nowIso: string = new Date().toISOString(),
): DeadlineStatus {
  const anchor = new Date(anchorIso);
  const now = new Date(nowIso);
  if (Number.isNaN(anchor.getTime())) {
    throw new Error(`deadlineStatus: invalid anchor date "${anchorIso}"`);
  }
  const basis: DeadlineStatus['basis'] = window.businessDays != null ? 'business-days' : 'calendar-days';
  const due = window.businessDays != null
    ? addBusinessDays(anchor, window.businessDays)
    : new Date(anchor.getTime() + (window.calendarDays ?? 0) * DAY_MS);
  const daysPast = basis === 'business-days' ? businessDaysBetween(due, now) : calendarDaysBetween(due, now);
  return {
    due: due.toISOString(),
    now: now.toISOString(),
    overdue: now.getTime() > due.getTime(),
    days_past_due: daysPast,
    basis,
  };
}
