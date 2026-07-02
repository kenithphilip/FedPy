/**
 * LOOP-B.B4 — Pure view-logic for the compensating-controls UI.
 *
 * The tracker toolchain has no jsdom / @testing-library, and vitest only collects
 * `server/**` + `tests/**` — so the React components can't be unit-rendered here.
 * Instead the components' decision logic (form validation, submit-enable, role-gated
 * CTAs, NIST-id suggestions) lives as pure functions and is unit-tested directly in
 * `tracker/tests/compensating-control-view.test.ts`. The components import these
 * helpers so the tested rules ARE the rendered behaviour (same pattern as B.B3's
 * risk-acceptance-view.ts).
 */

export type ControlStatus = 'draft' | 'active' | 'retired';

export const MIN_TITLE = 5;
export const MAX_TITLE = 200;
export const MIN_DESCRIPTION = 200;
export const MIN_RETIREMENT_REASON = 30;

export interface CompensatingControlFormState {
  title: string;
  description: string;
  nist_control_ids: string[];
  evidence_url: string;         // optional; '' = omitted
  expiration_date: string;      // optional ISO date; '' = no expiration
}

/**
 * Normalise a control id to the catalog key form: lowercase, `AC-2(3)` → `ac-2.3`.
 * Byte-identical to the server (nist-catalog.ts) + cloud-evidence (nist-r5.ts) so a
 * suggestion the UI accepts validates identically on POST.
 */
export function normalizeControlId(id: string): string {
  return String(id).trim().toLowerCase().replace(/\((\d+)\)/g, '.$1');
}

/** Validate the create/edit form; returns human-readable problems (empty = OK). */
export function validateControlForm(s: CompensatingControlFormState): string[] {
  const errs: string[] = [];
  const title = s.title.trim();
  if (title.length < MIN_TITLE || title.length > MAX_TITLE) {
    errs.push(`Title must be ${MIN_TITLE}-${MAX_TITLE} characters (currently ${title.length}).`);
  }
  if (s.description.length < MIN_DESCRIPTION) {
    errs.push(`Description must be at least ${MIN_DESCRIPTION} characters (currently ${s.description.length}).`);
  }
  if (s.nist_control_ids.length === 0) {
    errs.push('At least one NIST 800-53 control id is required.');
  }
  if (s.expiration_date) {
    const ms = Date.parse(s.expiration_date);
    if (!Number.isFinite(ms)) errs.push('Expiration date must be a valid date.');
  }
  return errs;
}

/** Submit is enabled only when the form has zero validation problems. */
export function canSubmitControlForm(s: CompensatingControlFormState): boolean {
  return validateControlForm(s).length === 0;
}

/** Characters still needed before the description meets the ≥200 floor (drives the red-tint). */
export function descriptionRemaining(text: string): number {
  return Math.max(0, MIN_DESCRIPTION - text.length);
}

// ─── Role-gated CTAs (mirror the server's rbac.ts permission model) ───────────
/** "New Control" + edit-draft CTA — iso/admin implement compensating controls. */
export function canCreateControl(role: string): boolean {
  return role === 'iso' || role === 'admin';
}
/** "Activate" (AO sign-off) — ao/admin, and only for a draft. */
export function canActivateControl(role: string, status: ControlStatus): boolean {
  return (role === 'ao' || role === 'admin') && status === 'draft';
}
/** "Retire" — iso/ao/admin, and only for an active control. */
export function canRetireControl(role: string, status: ControlStatus): boolean {
  return (role === 'iso' || role === 'ao' || role === 'admin') && status === 'active';
}
/** Whether the "Compensating Controls" nav link should be shown for this role. */
export function canViewCompensatingControls(role: string): boolean {
  return ['viewer', 'contributor', 'ksi-owner', 'auditor', 'iso', 'ao', 'assessor', 'admin'].includes(role);
}

export interface ControlCatalogEntry { id: string; name: string | null }

/**
 * Autocomplete suggestions for the NIST-id chip input: catalog entries whose id or
 * title contains the query (case-insensitive, normalised), capped to `limit`.
 * Fed a catalog list by the page; returns [] for a blank query.
 */
export function filterControlSuggestions(query: string, catalog: ControlCatalogEntry[], limit = 10): ControlCatalogEntry[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const nq = normalizeControlId(query);
  const out: ControlCatalogEntry[] = [];
  for (const entry of catalog) {
    const idKey = normalizeControlId(entry.id);
    const nameHit = (entry.name ?? '').toLowerCase().includes(q);
    if (idKey.includes(nq) || idKey.includes(q) || nameHit) {
      out.push(entry);
      if (out.length >= limit) break;
    }
  }
  return out;
}
