/**
 * MAS reconciliation — Minimum Assessment Scope drift detector.
 *
 * Per docs/analysis/ads-mas-csx.md (MAS-CSO-IIR is the anchor cross-check):
 * the *documented* assessment-scope resource set cannot be tested directly,
 * but it CAN be reconciled against the live, discovered inventory that
 * providers/{aws,gcp}/inventory.ts already enumerates (AWS Config Aggregator
 * resources / GCP Cloud Asset Inventory assets). The diff surfaces:
 *
 *   - undocumented (discovered ∉ documented)  → potential boundary GAP /
 *     scope drift: a live resource the MAS document doesn't cover.
 *   - missing      (documented ∉ discovered)  → drift / decommissioned: a
 *     documented resource with no discovered backing (stale scope doc).
 *   - in_both                                 → reconciled.
 *
 * This module is PURE (no I/O): callers supply the two identifier sets. The
 * collector cannot decide "likely handles federal data" — that scoping
 * judgment is human — so buildMasFindings() emits undocumented resources as a
 * gap for human review and says so explicitly.
 *
 * Reused by ADS-CSO-SVC (service-list under-disclosure), MAS-CSO-FLO,
 * MAS-CSO-TPR and KSI-CSX-MAS, all of which are the same diff over a different
 * pair of sets.
 */
import type { Finding, ImpactTier, KeyWord, AffectedResource } from './envelope.ts';
import { finding, severityForKeyWord } from './findings.ts';

export interface MasReconcileInput {
  /** Resource identifiers the provider has documented as in the assessment scope. */
  documented: string[];
  /** Resource identifiers discovered live in the environment (inventory.ts). */
  discovered: string[];
  /**
   * Optional normalizer applied to every identifier before comparison
   * (e.g. lowercase, strip account-id prefix). Defaults to identity-with-trim.
   */
  normalize?: (id: string) => string;
}

export interface MasReconcileResult {
  /** Identifiers present in BOTH sets (reconciled). Sorted, de-duplicated. */
  in_both: string[];
  /** Discovered but NOT documented → potential scope drift (in-scope resource missing from the MAS doc). */
  undocumented: string[];
  /** Documented but NOT discovered → drift / decommissioned (stale MAS doc entry). */
  missing: string[];
  /** undocumented.length + missing.length — total reconciliation drift. */
  drift_count: number;
  /** Counts for quick rollup. */
  counts: { documented: number; discovered: number; in_both: number; undocumented: number; missing: number };
}

const defaultNormalize = (id: string): string => id.trim();

/**
 * Diff a documented assessment-scope resource set against discovered inventory.
 * Pure + deterministic: blank/whitespace identifiers are dropped; duplicates
 * collapse; output arrays are sorted.
 */
export function reconcileMas(input: MasReconcileInput): MasReconcileResult {
  const norm = input.normalize ?? defaultNormalize;
  const clean = (xs: string[]): Set<string> => {
    const s = new Set<string>();
    for (const raw of xs ?? []) {
      if (typeof raw !== 'string') continue;
      const n = norm(raw);
      if (n.length > 0) s.add(n);
    }
    return s;
  };

  const doc = clean(input.documented);
  const disc = clean(input.discovered);

  const in_both: string[] = [];
  const undocumented: string[] = [];
  const missing: string[] = [];

  for (const d of disc) {
    if (doc.has(d)) in_both.push(d);
    else undocumented.push(d);
  }
  for (const d of doc) {
    if (!disc.has(d)) missing.push(d);
  }

  in_both.sort();
  undocumented.sort();
  missing.sort();

  return {
    in_both,
    undocumented,
    missing,
    drift_count: undocumented.length + missing.length,
    counts: {
      documented: doc.size,
      discovered: disc.size,
      in_both: in_both.length,
      undocumented: undocumented.length,
      missing: missing.length,
    },
  };
}

/**
 * Tier → obligation strength for MAS-CSO-IIR. All MAS requirements are
 * L:✓ M:✓ H:derived; MAS-CSO-IIR is a MUST at Low and Moderate, and High is
 * derived-pending — we still treat the boundary obligation as MUST.
 */
function masKeyWord(_tier: ImpactTier): KeyWord {
  return 'MUST';
}

const MAS_NIST_CONTROLS = ['cm-8', 'cm-8.1', 'pm-5'];

function toAffected(ids: string[], reason: string): AffectedResource[] {
  return ids.map((id) => ({
    type: 'fedramp_assessment_scope_resource',
    identifier: id,
    name: id,
    attributes: { reconciliation: reason },
  }));
}

/**
 * Build MAS reconciliation findings (MAS-CSO-IIR anchor).
 *
 * Two findings:
 *   1. boundary_drift — fails if there is ANY drift (undocumented or missing).
 *      Undocumented resources are flagged as a potential scope GAP; the note
 *      makes explicit that the human still owns the "likely handles federal
 *      data" judgment.
 *   2. no_undocumented_resources — focused signal for under-scoping (the
 *      higher-risk half: live resources not in the MAS document).
 *
 * Never throws. If both sets are empty it returns an informational
 * missing-evidence-style finding rather than a false pass.
 */
export function buildMasFindings(result: MasReconcileResult, tier: ImpactTier): Finding[] {
  const kw = masKeyWord(tier);
  const findings: Finding[] = [];

  const noInputs = result.counts.documented === 0 && result.counts.discovered === 0;

  // ── Finding 1: overall boundary drift ────────────────────────────────────
  const driftClean = !noInputs && result.drift_count === 0;
  findings.push(
    finding({
      rule: 'mas.cso.iir.boundary_reconciled',
      passed: driftClean,
      severity: severityForKeyWord(kw, 'high'),
      applicable_key_word: kw,
      current: {
        summary: noInputs
          ? 'No documented MAS resource set AND no discovered inventory supplied — reconciliation could not run.'
          : driftClean
            ? `Documented assessment scope reconciles with discovered inventory (${result.counts.in_both} resources, 0 drift).`
            : `MAS reconciliation found ${result.drift_count} drift item(s): ${result.counts.undocumented} undocumented (discovered∉documented), ${result.counts.missing} missing (documented∉discovered).`,
        observations: {
          counts: result.counts,
          undocumented: result.undocumented,
          missing: result.missing,
          drift_count: result.drift_count,
        },
      },
      target: {
        summary: 'Every discovered in-scope information resource is reflected in the documented Minimum Assessment Scope, and every documented resource is still live.',
        rationale:
          'FedRAMP 20x MAS-CSO-IIR: the set of information resources to assess "is" the cloud service offering. ' +
          'A read-only collector reconciles the documented scope against live inventory to surface candidate boundary gaps; ' +
          'NIST CM-8 (system component inventory). High applicability is derived-rev5-pending (no controls[] to anchor).',
      },
      gap: driftClean
        ? undefined
        : {
            description: noInputs
              ? 'Reconciliation had no inputs: supply the documented MAS resource set and/or discovered inventory identifiers.'
              : `${result.drift_count} resource(s) do not reconcile between the documented MAS and discovered inventory. ` +
                'Undocumented resources are candidate scope gaps; missing resources indicate a stale/decommissioned MAS entry.',
            affected_resources: noInputs
              ? [{
                  type: 'fedramp_assessment_scope_resource',
                  identifier: 'minimum-assessment-scope',
                  name: 'MAS reconciliation unreadable — no documented scope or discovered inventory supplied (indeterminate)',
                  attributes: { reconciliation: 'no-inputs' },
                }]
              : [
                  ...toAffected(result.undocumented, 'discovered-but-undocumented'),
                  ...toAffected(result.missing, 'documented-but-undiscovered'),
                ],
          },
      remediation: driftClean
        ? undefined
        : {
            summary: 'Reconcile the documented Minimum Assessment Scope with live inventory; a human must judge which discovered resources are in scope.',
            options: [
              {
                approach: 'Review each drift item and update the MAS document (or the documented IR set) accordingly.',
                mechanism: 'process',
                owner_team: 'Compliance',
                steps: [
                  'For each UNDOCUMENTED (discovered∉documented) resource, decide whether it is likely to handle federal customer data or impact its CIA — if so, add it to the MAS document.',
                  'For each MISSING (documented∉discovered) resource, confirm it was intentionally decommissioned and remove the stale entry, or restore discovery (permissions/region scope) if it should still appear.',
                  'Record the scoping rationale per resource so the assessor can trace the boundary decision.',
                  'Re-run cloud-evidence to confirm the boundary reconciles.',
                ],
                cost_impact: { level: 'none', notes: 'Documentation / scoping effort only.' },
                availability_impact: { level: 'none', notes: 'No system change.' },
                customer_visible: { level: 'none', notes: 'Internal boundary documentation.' },
                effort_estimate: { magnitude: 'hours', notes: 'Scales with drift count; recurring as inventory changes.' },
                references: [
                  { title: 'NIST SP 800-53 CM-8', url: 'https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-8/' },
                ],
              },
            ],
          },
      nist_controls: MAS_NIST_CONTROLS,
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-PIY-GIV', relationship: 'depends-on', note: 'Discovered inventory is sourced from the PIY-GIV inventory collectors (Config Aggregator / Cloud Asset Inventory).' },
        { ksi_id: 'ADS-CSO-SVC', relationship: 'shares-remediation', note: 'Same reconciliation engine cross-checks the public service list.' },
        { ksi_id: 'MAS-CSO-TPR', relationship: 'shares-remediation', note: 'Third-party resource reconciliation reuses this diff over the subprocessor/tool set.' },
      ],
      note:
        'The collector surfaces candidate scope drift only — it CANNOT decide whether a discovered resource is "likely to handle federal customer data" or impact its CIA. ' +
        'That MAS-CSO-IIR judgment is human-owned; treat undocumented resources as review candidates, not automatic failures of the boundary itself. ' +
        'High applicability is derived-rev5-pending (no controls[] to derive from).',
    }),
  );

  // ── Finding 2: focused under-disclosure signal ───────────────────────────
  const noUndocumented = !noInputs && result.undocumented.length === 0;
  findings.push(
    finding({
      rule: 'mas.cso.iir.no_undocumented_resources',
      passed: noUndocumented,
      severity: severityForKeyWord(kw, 'high'),
      applicable_key_word: kw,
      current: {
        summary: noInputs
          ? 'No inputs supplied — undocumented-resource check could not run.'
          : noUndocumented
            ? 'Every discovered resource appears in the documented assessment scope (no under-disclosure detected).'
            : `${result.undocumented.length} discovered resource(s) are not in the documented MAS — candidate scope gaps requiring human review.`,
        observations: { undocumented: result.undocumented, undocumented_count: result.undocumented.length },
      },
      target: {
        summary: 'No live resource that customers can reach is absent from the documented Minimum Assessment Scope.',
        rationale:
          'Under-disclosure (a live resource outside the documented boundary) is the higher-risk half of MAS drift — it can let an in-scope resource escape assessment. NIST CM-8.',
      },
      gap: noUndocumented
        ? undefined
        : {
            description: 'Discovered resources are missing from the documented MAS. A human must judge whether each is in scope (likely handles federal customer data).',
            affected_resources: noInputs
              ? [{
                  type: 'fedramp_assessment_scope_resource',
                  identifier: 'minimum-assessment-scope',
                  name: 'undocumented-resource check unreadable — no documented scope or discovered inventory supplied (indeterminate)',
                  attributes: { reconciliation: 'no-inputs' },
                }]
              : toAffected(result.undocumented, 'discovered-but-undocumented'),
          },
      remediation: noUndocumented
        ? undefined
        : {
            summary: 'Add the in-scope discovered resources to the MAS document after the human scoping judgment.',
            options: [
              {
                approach: 'Triage each undocumented resource for federal-data handling and update the MAS.',
                mechanism: 'process',
                owner_team: 'Compliance',
                steps: [
                  'Classify each undocumented resource: does it handle federal customer data or impact its CIA?',
                  'Add in-scope resources to the MAS document with a security objective.',
                  'Explicitly exclude (with rationale) resources that only handle provider telemetry/metadata.',
                ],
                cost_impact: { level: 'none', notes: 'Scoping effort.' },
                availability_impact: { level: 'none', notes: 'No system change.' },
                customer_visible: { level: 'none', notes: 'Internal.' },
                effort_estimate: { magnitude: 'hours', notes: 'Per resource.' },
              },
            ],
          },
      nist_controls: MAS_NIST_CONTROLS,
      note: 'Human-owned judgment: only the operator can confirm a discovered resource is in-scope. Undocumented ≠ automatic noncompliance.',
    }),
  );

  return findings;
}
