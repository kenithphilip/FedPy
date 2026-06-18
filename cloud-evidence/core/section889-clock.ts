/**
 * Federal-business-day clock for the FAR 52.204-25(d) 1-business-day prohibited-
 * vendor discovery reporter (LOOP-W.W3).
 *
 * FAR 52.204-25(d)(2)(i) obliges a contractor that discovers covered
 * telecommunications equipment or services to report to the Contracting Officer
 * "within one business day from the date of such identification or
 * notification". The Joint FAR Council's Part B final-rule preamble (84 FR /
 * 85 FR) reads that window as a federal-government business day: Monday–Friday,
 * 09:00–17:00 in the National Capital Region (America/New_York), excluding the
 * 11 federal holidays under 5 U.S.C. §6103 and any one-off agency-closure day
 * proclaimed by the President under §6103(c). One federal business day = 8
 * federal business hours.
 *
 * This module computes that deadline. It COMPOSES the federal-holiday calendar
 * from `core/bizdays.ts` (`usFederalHolidays`, which derives the observed
 * holidays per year from 5 U.S.C. §6103 with the OPM in-lieu-of rule) rather
 * than re-deriving them — so the holiday set stays correct across years without
 * a second source of truth. It adds the hour-level + timezone + DST layer that
 * bizdays.ts (which is day-granular) does not provide:
 *
 *   - 8 business hours per business day (09:00–17:00 ET by default);
 *   - exclusion of Saturdays, Sundays, and the federal holidays;
 *   - operator agency-closure days (one-off proclaimed closures);
 *   - DST correctness: all wall-clock arithmetic is performed in
 *     America/New_York via the IANA tz database exposed through
 *     `Intl.DateTimeFormat`, so the spring-forward / fall-back transitions
 *     (which occur at 02:00, outside business hours) never introduce an
 *     off-by-one-hour error.
 *
 * Pure functions, no I/O. Deadlines are returned as UTC ISO-8601 instants
 * (the canonical envelope representation); they denote the same instant as the
 * equivalent America/New_York wall-clock time.
 */
import { usFederalHolidays } from './bizdays.ts';

export const DEFAULT_BUSINESS_TZ = 'America/New_York';
export const DEFAULT_OPEN_HOUR = 9;
export const DEFAULT_CLOSE_HOUR = 17;
/** One federal business day, in federal business hours. */
export const FEDERAL_BUSINESS_HOURS_PER_DAY = 8;

export interface FederalClockOptions {
  /** IANA time zone the business day is reckoned in. Default America/New_York. */
  tz?: string;
  /** Business-day open hour (local), default 9 (09:00). */
  openHour?: number;
  /** Business-day close hour (local), default 17 (17:00). */
  closeHour?: number;
  /** Business hours that make up one business day, default 8. */
  businessHoursPerDay?: number;
  /**
   * Operator agency-closure dates (one-off proclaimed §6103(c) closures) as
   * `YYYY-MM-DD` strings in the business time zone. These are excluded in
   * addition to weekends + federal holidays.
   */
  extraClosures?: Set<string> | string[];
}

interface ResolvedOptions {
  tz: string;
  openHour: number;
  closeHour: number;
  perDay: number;
  closures: Set<string>;
}

function resolve(opts: FederalClockOptions = {}): ResolvedOptions {
  const closures = opts.extraClosures instanceof Set
    ? opts.extraClosures
    : new Set(opts.extraClosures ?? []);
  return {
    tz: opts.tz ?? DEFAULT_BUSINESS_TZ,
    openHour: opts.openHour ?? DEFAULT_OPEN_HOUR,
    closeHour: opts.closeHour ?? DEFAULT_CLOSE_HOUR,
    perDay: opts.businessHoursPerDay ?? FEDERAL_BUSINESS_HOURS_PER_DAY,
    closures,
  };
}

interface WallClock {
  year: number;
  month: number; // 1-12
  day: number;
  hour: number;
  minute: number;
  second: number;
}

const _fmtCache = new Map<string, Intl.DateTimeFormat>();
function formatter(tz: string): Intl.DateTimeFormat {
  let f = _fmtCache.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hourCycle: 'h23',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    _fmtCache.set(tz, f);
  }
  return f;
}

/** The wall-clock components of a UTC instant in the given IANA time zone. */
function wallClockOf(instant: Date, tz: string): WallClock {
  const parts = formatter(tz).formatToParts(instant);
  const m: Record<string, string> = {};
  for (const p of parts) if (p.type !== 'literal') m[p.type] = p.value;
  return {
    year: Number(m.year),
    month: Number(m.month),
    day: Number(m.day),
    // 'h23' renders midnight as 00, but some engines render 24 — normalize.
    hour: Number(m.hour) % 24,
    minute: Number(m.minute),
    second: Number(m.second),
  };
}

/** Minutes that `tz` is ahead of UTC at `instant` (negative west of UTC). */
function offsetMinutes(instant: Date, tz: string): number {
  const w = wallClockOf(instant, tz);
  const asUtc = Date.UTC(w.year, w.month - 1, w.day, w.hour, w.minute, w.second);
  return Math.round((asUtc - instant.getTime()) / 60000);
}

/**
 * The UTC instant for a wall-clock time in `tz`. Two-pass offset correction so
 * the result is exact even across DST transitions (business-hour times never
 * fall in the ambiguous/skipped 02:00–03:00 window, so one pass already
 * converges; the second pass is belt-and-suspenders).
 */
function instantOf(w: WallClock, tz: string): Date {
  const guess = Date.UTC(w.year, w.month - 1, w.day, w.hour, w.minute, w.second);
  let off = offsetMinutes(new Date(guess), tz);
  let dt = new Date(guess - off * 60000);
  off = offsetMinutes(dt, tz);
  dt = new Date(guess - off * 60000);
  return dt;
}

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

/** `YYYY-MM-DD` for a wall-clock date. */
function dateKey(year: number, month: number, day: number): string {
  return `${year}-${pad(month)}-${pad(day)}`;
}

/** Day-of-week (0=Sun..6=Sat) for a calendar date, via a UTC-noon anchor. */
function weekdayOf(year: number, month: number, day: number): number {
  return new Date(Date.UTC(year, month - 1, day, 12, 0, 0)).getUTCDay();
}

/**
 * Is the given calendar date (in the business time zone) a federal business
 * day — not a weekend, not a 5 U.S.C. §6103 federal holiday, not an operator
 * agency-closure day?
 */
export function isFederalBusinessDate(
  year: number, month: number, day: number, opts: FederalClockOptions = {},
): boolean {
  const { closures } = resolve(opts);
  const dow = weekdayOf(year, month, day);
  if (dow === 0 || dow === 6) return false;
  const key = dateKey(year, month, day);
  if (usFederalHolidays(year).has(key)) return false;
  if (closures.has(key)) return false;
  return true;
}

/** Advance to the next federal business date strictly after the given one. */
function nextBusinessDate(
  year: number, month: number, day: number, opts: FederalClockOptions,
): { year: number; month: number; day: number } {
  // Step one calendar day at a time via a UTC anchor, re-reading Y/M/D.
  let cursor = Date.UTC(year, month - 1, day, 12, 0, 0);
  for (let i = 0; i < 3700; i++) { // bounded: > 10 years of daily steps
    cursor += 86_400_000;
    const d = new Date(cursor);
    const y = d.getUTCFullYear(), mo = d.getUTCMonth() + 1, da = d.getUTCDate();
    if (isFederalBusinessDate(y, mo, da, opts)) return { year: y, month: mo, day: da };
  }
  throw new Error('section889-clock: no federal business day found within 10 years (corrupt holiday/closure set?)');
}

interface BusinessCursor {
  year: number;
  month: number;
  day: number;
  /** Hour-of-day as a float in [openHour, closeHour]. */
  hourFloat: number;
}

/**
 * Clamp a wall-clock instant to the first business-hour instant at or after it:
 * within hours on a business date → unchanged; before open on a business date →
 * that day's open; at/after close, or on a non-business date → the next
 * business day's open.
 */
function clampToBusinessOpen(w: WallClock, r: ResolvedOptions): BusinessCursor {
  const hourFloat = w.hour + w.minute / 60 + w.second / 3600;
  const onBusinessDate = isFederalBusinessDate(w.year, w.month, w.day, { tz: r.tz, extraClosures: r.closures });
  if (onBusinessDate && hourFloat >= r.openHour && hourFloat < r.closeHour) {
    return { year: w.year, month: w.month, day: w.day, hourFloat };
  }
  if (onBusinessDate && hourFloat < r.openHour) {
    return { year: w.year, month: w.month, day: w.day, hourFloat: r.openHour };
  }
  const nb = nextBusinessDate(w.year, w.month, w.day, { tz: r.tz, extraClosures: r.closures });
  return { year: nb.year, month: nb.month, day: nb.day, hourFloat: r.openHour };
}

function cursorToInstant(c: BusinessCursor, tz: string): Date {
  const hour = Math.floor(c.hourFloat);
  const minuteFloat = (c.hourFloat - hour) * 60;
  const minute = Math.floor(minuteFloat + 1e-9);
  const second = Math.round((minuteFloat - minute) * 60);
  return instantOf({ year: c.year, month: c.month, day: c.day, hour, minute, second }, tz);
}

/**
 * Compute the instant `businessHours` federal business hours after `startIso`,
 * carrying across nights / weekends / holidays / closures. Returns a UTC ISO
 * instant. The clock first clamps `startIso` to the next business-hour boundary
 * (a discovery at 18:00 Friday starts ticking at 09:00 Monday).
 */
export function addFederalBusinessHours(
  startIso: string, businessHours: number, opts: FederalClockOptions = {},
): string {
  const r = resolve(opts);
  const start = new Date(startIso);
  if (Number.isNaN(start.getTime())) {
    throw new Error(`section889-clock: invalid start instant "${startIso}"`);
  }
  if (businessHours <= 0) {
    const clamped = clampToBusinessOpen(wallClockOf(start, r.tz), r);
    return cursorToInstant(clamped, r.tz).toISOString();
  }
  let cur = clampToBusinessOpen(wallClockOf(start, r.tz), r);
  let remaining = businessHours;
  // Bounded loop: each iteration consumes at least one business day.
  for (let i = 0; i < 100_000; i++) {
    const available = r.closeHour - cur.hourFloat;
    if (available >= remaining) {
      const end: BusinessCursor = { ...cur, hourFloat: cur.hourFloat + remaining };
      return cursorToInstant(end, r.tz).toISOString();
    }
    remaining -= available;
    const nb = nextBusinessDate(cur.year, cur.month, cur.day, { tz: r.tz, extraClosures: r.closures });
    cur = { year: nb.year, month: nb.month, day: nb.day, hourFloat: r.openHour };
  }
  throw new Error('section889-clock: deadline computation did not converge');
}

/**
 * The FAR 52.204-25(d)(2)(i) 1-business-day deadline for a discovery instant:
 * one federal business day (8 business hours by default) after discovery.
 */
export function deadlineFor(discoveryIso: string, opts: FederalClockOptions = {}): string {
  const r = resolve(opts);
  return addFederalBusinessHours(discoveryIso, r.perDay, opts);
}

/**
 * The FAR 52.204-25(d)(2)(ii) follow-up deadline: `businessDays` federal
 * business days (default 10) after the anchor instant. The (d)(2)(ii) clock
 * runs from initial-report submission; W.W3 anchors on discovery as the
 * conservative earliest start when no operator transmission time is recorded.
 */
export function followUpDeadlineFor(
  anchorIso: string, businessDays = 10, opts: FederalClockOptions = {},
): string {
  const r = resolve(opts);
  return addFederalBusinessHours(anchorIso, r.perDay * businessDays, opts);
}

/**
 * Federal business hours elapsed between two instants (>= 0). Used to surface
 * `business_hours_remaining_at_emit` on the report envelope.
 */
export function federalBusinessHoursBetween(
  startIso: string, endIso: string, opts: FederalClockOptions = {},
): number {
  const r = resolve(opts);
  const start = new Date(startIso);
  const end = new Date(endIso);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    throw new Error('section889-clock: invalid instant in federalBusinessHoursBetween');
  }
  if (end.getTime() <= start.getTime()) return 0;
  let cur = clampToBusinessOpen(wallClockOf(start, r.tz), r);
  let curInstant = cursorToInstant(cur, r.tz).getTime();
  if (curInstant >= end.getTime()) return 0;
  let elapsed = 0;
  for (let i = 0; i < 100_000; i++) {
    const closeInstant = cursorToInstant({ ...cur, hourFloat: r.closeHour }, r.tz).getTime();
    if (closeInstant >= end.getTime()) {
      elapsed += (end.getTime() - curInstant) / 3_600_000;
      return +elapsed.toFixed(4);
    }
    elapsed += (closeInstant - curInstant) / 3_600_000;
    const nb = nextBusinessDate(cur.year, cur.month, cur.day, { tz: r.tz, extraClosures: r.closures });
    cur = { year: nb.year, month: nb.month, day: nb.day, hourFloat: r.openHour };
    curInstant = cursorToInstant(cur, r.tz).getTime();
    if (curInstant >= end.getTime()) return +elapsed.toFixed(4);
  }
  throw new Error('section889-clock: elapsed computation did not converge');
}

/**
 * Business hours remaining from `nowIso` until `deadlineIso` (>= 0; 0 when the
 * deadline has passed). Negative budgets are clamped to 0 — a breached deadline
 * is surfaced by the boolean, not by a negative number.
 */
export function businessHoursRemaining(
  nowIso: string, deadlineIso: string, opts: FederalClockOptions = {},
): number {
  const now = new Date(nowIso).getTime();
  const deadline = new Date(deadlineIso).getTime();
  if (Number.isNaN(now) || Number.isNaN(deadline)) {
    throw new Error('section889-clock: invalid instant in businessHoursRemaining');
  }
  if (now >= deadline) return 0;
  return federalBusinessHoursBetween(nowIso, deadlineIso, opts);
}
