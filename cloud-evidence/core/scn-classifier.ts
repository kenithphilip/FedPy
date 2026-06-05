/**
 * Significant Change Notification (SCN) classifier — SCN-1.
 *
 * FedRAMP requires CSPs to notify their authorizing agency before making a
 * **significant change** to an authorized cloud service offering — typically
 * 30 days in advance — and to include specific artifacts (updated SSP, updated
 * FIPS-199 categorization, POA&M, etc.) depending on the change type.
 *
 * This module bootstraps that pipeline. It harvests "changes" from the data we
 * already produce in a run:
 *   - `diff-report.json`         — regressed / new findings between two runs
 *   - `inventory-diff.json`      — added / removed / mutated cloud assets
 *   - an optional proposed-changes JSON manifest (forward-looking)
 *
 * It then runs each change through a rule library (FedRAMP-categorised) to
 * label it `significant` / `advisory` / `not-significant`, attach a recommended
 * notification window in days, and list the artifacts the change requires.
 *
 * Clean-room from the huntridge-labs/argus AGPL project (research report 08 — idea
 * source only, no code copied). The rule taxonomy, the FedPy-native data shapes
 * (diff-report.json + inventory-diff.json), the predicate implementations, and the
 * draft-notice generator are all original to this codebase.
 *
 * Pure core (`classifyChange`, `classifyChanges`, `harvestChanges`,
 * `draftNotice`) + a thin disk reader/writer (`buildScnReport`, `writeScnReport`).
 * Read-only.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { InventoryDiff } from './inventory-emit.ts';

// ───────────────────────────── Types ─────────────────────────────

export type Significance = 'significant' | 'advisory' | 'not-significant';

export type ScnCategory =
  | 'boundary'           // new region / account / subscription / project; component crossing the boundary
  | 'authentication'     // IdP swap, MFA enforcement change
  | 'cryptography'       // KMS / Key Vault key add/remove; CMK source change; encryption-mechanism swap
  | 'network'            // public exposure change, new public-facing endpoint, NSG/SG opened
  | 'data-flow'          // new external integration / egress destination
  | 'personnel'          // new admin / privileged role assignment
  | 'platform-version'   // major version upgrade (K8s, OS, DB engine)
  | 'subprocessor'       // new third-party subprocessor / sub-CSP
  | 'configuration'      // generic in-scope config regression
  | 'improvement'        // formerly-failing finding now passes — never a notification trigger
  | 'other';

export interface ScnChange {
  /** Stable identifier (used to dedupe + cross-reference across runs). */
  id: string;
  /** Human-readable description (renders into the draft notice). */
  description: string;
  /** Where the change was observed. */
  source: 'finding-diff' | 'inventory-diff' | 'proposed';
  /** Categorical type (drives rule matching). */
  category: ScnCategory;
  /** Affected resources / artifacts; rendered into the notice. */
  affected?: Array<{ type: string; identifier: string }>;
  /** Raw evidence (the original diff record) for traceability. */
  raw?: unknown;
}

export interface ScnClassification {
  change: ScnChange;
  significance: Significance;
  /** The id of the rule that matched (or 'default' when none did). */
  rule_id: string;
  rationale: string;
  /** Days of advance notice recommended for the agency (null when not significant). */
  recommended_notice_days: number | null;
  /** Artifacts the CSP must include in / produce alongside the notification. */
  required_artifacts: string[];
}

export interface ScnReport {
  run_id: string;
  generated_at: string;
  totals: { significant: number; advisory: number; not_significant: number; total: number };
  classifications: ScnClassification[];
  draft_notice: string;
}

export interface ScnRule {
  id: string;
  description: string;
  category?: ScnCategory;
  /** Optional predicate for finer-grained matching beyond the category filter. */
  matches?: (c: ScnChange) => boolean;
  significance: Significance;
  recommended_notice_days: number | null;
  required_artifacts: string[];
}

// ───────────────────────────── Default rules ─────────────────────────────

/**
 * Curated rule set covering the FedRAMP "significant change" taxonomy
 * (SP 800-37 r2 § 3.6 + the FedRAMP SCR guide). Order matters — first match wins.
 * Caller can pass their own rules to `classifyChange`/`buildScnReport`.
 */
export const DEFAULT_RULES: ScnRule[] = [
  {
    id: 'scn-r-boundary-new',
    description: 'New authorization-boundary scope (region / account / subscription / project).',
    category: 'boundary',
    significance: 'significant',
    recommended_notice_days: 30,
    required_artifacts: [
      'Updated SSP authorization-boundary diagram',
      'Updated FIPS-199 categorization (if data sensitivity changes)',
      'Updated POA&M reflecting net-new controls in scope',
      'Updated inventory workbook (Appendix M)',
    ],
  },
  {
    id: 'scn-r-auth-swap',
    description: 'Change to authentication mechanism (IdP add/remove, MFA enforcement change).',
    category: 'authentication',
    significance: 'significant',
    recommended_notice_days: 30,
    required_artifacts: [
      'Updated SSP IA-2 / IA-5 control narratives',
      'IdP integration documentation (SAML/OIDC metadata, SCIM scope)',
      'Conditional Access / SCP / IAM-policy snapshot showing enforcement',
    ],
  },
  {
    id: 'scn-r-crypto-replace',
    description: 'Replacement / removal of an in-scope cryptographic mechanism (CMK, FIPS module, TLS profile).',
    category: 'cryptography',
    significance: 'significant',
    recommended_notice_days: 30,
    required_artifacts: [
      'Updated SSP SC-12 / SC-13 / SC-28 narratives',
      'FIPS 140-3 validation certificate for the new module',
      'Key-rotation runbook reflecting the new mechanism',
    ],
  },
  {
    id: 'scn-r-network-arch',
    description: 'Network-architecture change with external exposure (new public endpoint, new VPC peering / VNet peering).',
    category: 'network',
    significance: 'significant',
    recommended_notice_days: 30,
    required_artifacts: [
      'Updated SSP SC-7 narrative + boundary diagram',
      'Network-architecture diagram (with the new flow)',
      'Threat-model delta for the new exposure',
    ],
  },
  {
    id: 'scn-r-data-flow-new',
    description: 'New external data-flow / integration leaving the authorization boundary.',
    category: 'data-flow',
    significance: 'significant',
    recommended_notice_days: 30,
    required_artifacts: [
      'Updated data-flow diagram',
      'Vendor SLA / FedRAMP authorization for the destination service',
      'Updated SSP AC-4 / SC-7 narratives',
    ],
  },
  {
    id: 'scn-r-subprocessor-new',
    description: 'New third-party subprocessor / sub-CSP added to the offering.',
    category: 'subprocessor',
    significance: 'significant',
    recommended_notice_days: 30,
    required_artifacts: [
      'Subprocessor inventory update (CSX-SUM input)',
      'Subprocessor FedRAMP authorization status (or compensating evidence)',
      'DPA / customer-notice update',
    ],
  },
  {
    id: 'scn-r-personnel-admin',
    description: 'New privileged role assignment / admin grant inside the authorization boundary.',
    category: 'personnel',
    significance: 'significant',
    recommended_notice_days: 30,
    required_artifacts: [
      'Updated personnel roster (PS-6 / PS-7)',
      'Background-investigation status of the new principal',
      'Updated SSP AC-2 / AC-6 narratives',
    ],
  },
  {
    id: 'scn-r-platform-major',
    description: 'Major version upgrade of a core platform component (Kubernetes, OS, database engine).',
    category: 'platform-version',
    significance: 'advisory',
    recommended_notice_days: 14,
    required_artifacts: [
      'Updated SSP component table',
      'Vendor release notes + security advisories addressed by the upgrade',
      'Rollback plan',
    ],
  },
  {
    id: 'scn-r-config-regressed',
    description: 'Previously-passing in-scope security control regressed.',
    category: 'configuration',
    significance: 'advisory',
    recommended_notice_days: 7,
    required_artifacts: [
      'POA&M entry for the regression with target remediation date',
      'Updated control-implementation narrative if the deviation is intentional',
    ],
  },
  {
    id: 'scn-r-improvement',
    description: 'Improvement (formerly failing finding now passes / asset hardened).',
    category: 'improvement',
    significance: 'not-significant',
    recommended_notice_days: null,
    required_artifacts: [],
  },
];

// ───────────────────────────── Pure classifier ─────────────────────────────

/** Run one change through the rule list — first match wins; otherwise `not-significant`. */
export function classifyChange(change: ScnChange, rules: ScnRule[] = DEFAULT_RULES): ScnClassification {
  for (const r of rules) {
    if (r.category && r.category !== change.category) continue;
    if (r.matches && !r.matches(change)) continue;
    return {
      change,
      significance: r.significance,
      rule_id: r.id,
      rationale: r.description,
      recommended_notice_days: r.recommended_notice_days,
      required_artifacts: [...r.required_artifacts],
    };
  }
  return {
    change,
    significance: 'not-significant',
    rule_id: 'default',
    rationale: 'No matching SCN rule — change is not classified as significant by default.',
    recommended_notice_days: null,
    required_artifacts: [],
  };
}

export function classifyChanges(changes: ScnChange[], rules: ScnRule[] = DEFAULT_RULES): ScnClassification[] {
  return changes.map((c) => classifyChange(c, rules));
}

// ───────────────────────── Diff → ScnChange harvester ─────────────────────────

// Lowercase substrings that map a finding rule or asset type → category.
const CATEGORY_HINTS: Array<{ pat: RegExp; category: ScnCategory }> = [
  { pat: /mfa|saml|oidc|sso|idp|identitystore|conditional.?access|root.?mfa/i, category: 'authentication' },
  { pat: /kms|cmek|cmk|key.?vault|encrypt|decrypt|crypt|tls|cipher/i, category: 'cryptography' },
  { pat: /vpc|peering|nsg|security.?group|firewall|public.?ip|public.?network|ingress|egress|cidr|subnet|loadbalancer|gateway|cloudfront/i, category: 'network' },
  { pat: /subscriptions?|projects?|accounts?|tenant|organization|management.?group/i, category: 'boundary' },
  { pat: /admin|owner|root|privileged|primitive.?role|policyAssignment|roleAssignment|iam.?role|service.?account/i, category: 'personnel' },
  { pat: /cloudtrail|audit|logging|diag|monitor|workspace|sentinel|securityhub|guardduty|defender|insight/i, category: 'configuration' },
  { pat: /kubernet|eks|gke|aks|version|os.?name|engine|patch/i, category: 'platform-version' },
];

function categorize(text: string): ScnCategory {
  for (const h of CATEGORY_HINTS) if (h.pat.test(text)) return h.category;
  return 'configuration';
}

/** Harvest changes from the structured outputs of a run. Pure: no fs reads. */
export function harvestChanges(opts: {
  diffSummary?: { ksi_diffs?: Array<{ ksi_id: string; finding_changes?: Array<{ rule: string; change: string; current?: any; previous?: any }> }> } | null;
  inventoryDiff?: InventoryDiff | null;
  proposed?: ScnChange[];
}): ScnChange[] {
  const out: ScnChange[] = [];

  // 1) Finding diffs — only regressions and new failing findings count; "fixed" → improvement.
  for (const ksi of opts.diffSummary?.ksi_diffs ?? []) {
    for (const fc of ksi.finding_changes ?? []) {
      const ruleStr = String(fc.rule ?? '');
      if (fc.change === 'fixed') {
        out.push({
          id: `finding-improved::${ksi.ksi_id}::${ruleStr}`,
          description: `Finding "${ruleStr}" (${ksi.ksi_id}) now passes (previously failing).`,
          source: 'finding-diff', category: 'improvement', raw: fc,
        });
      } else if (fc.change === 'regressed' || (fc.change === 'new' && fc.current?.passed === false)) {
        const cat = categorize(`${ksi.ksi_id} ${ruleStr}`);
        out.push({
          id: `finding-regressed::${ksi.ksi_id}::${ruleStr}`,
          description: `Finding "${ruleStr}" (${ksi.ksi_id}) ${fc.change === 'new' ? 'newly failing' : 'regressed'}.`,
          source: 'finding-diff', category: cat, raw: fc,
        });
      }
    }
  }

  // 2) Inventory diff — added / removed / mutated assets in scope-shaping categories.
  for (const id of opts.inventoryDiff?.added ?? []) {
    out.push({
      id: `inv-added::${id}`,
      description: `Asset added to the cloud inventory: ${id}.`,
      source: 'inventory-diff', category: categorize(id),
      affected: [{ type: 'cloud-asset', identifier: id }], raw: { added: id },
    });
  }
  for (const id of opts.inventoryDiff?.removed ?? []) {
    out.push({
      id: `inv-removed::${id}`,
      description: `Asset removed from the cloud inventory: ${id}.`,
      source: 'inventory-diff', category: categorize(id),
      affected: [{ type: 'cloud-asset', identifier: id }], raw: { removed: id },
    });
  }
  for (const ch of opts.inventoryDiff?.changed ?? []) {
    // Field-aware re-categorization for richer hints.
    const fields = ch.fields ?? [];
    let cat: ScnCategory;
    if (fields.includes('encryptionAtRest') || fields.includes('kmsKeyId')) cat = 'cryptography';
    else if (fields.includes('publicFacing')) cat = 'network';
    else if (fields.includes('osNameVersion') || fields.includes('softwareDatabaseNameVersion')) cat = 'platform-version';
    else cat = categorize(`${ch.id} ${fields.join(' ')}`);
    out.push({
      id: `inv-changed::${ch.id}::${fields.join(',')}`,
      description: `Asset ${ch.id} changed (${fields.join(', ')}).`,
      source: 'inventory-diff', category: cat,
      affected: [{ type: 'cloud-asset', identifier: ch.id }], raw: ch,
    });
  }

  // 3) Operator-supplied proposed changes (pre-categorized; pass through).
  if (opts.proposed) out.push(...opts.proposed);

  return out;
}

// ───────────────────────── Draft notice generator ─────────────────────────

/** Markdown stub the CSP can refine into a real agency notification email/letter. */
export function draftNotice(report: ScnReport, opts: { systemName?: string; csp?: string } = {}): string {
  const sig = report.classifications.filter((c) => c.significance === 'significant');
  const adv = report.classifications.filter((c) => c.significance === 'advisory');
  if (sig.length === 0 && adv.length === 0) {
    return `# Significant Change Notification (SCN) — none required\n\n` +
      `_Generated ${report.generated_at} from run ${report.run_id}._\n\n` +
      `No significant or advisory changes were detected in this run. No notification is required.`;
  }
  const sysLine = opts.systemName ? `**System:** ${opts.systemName}` : '**System:** _(fill in)_';
  const cspLine = opts.csp ? `**CSP:** ${opts.csp}` : '**CSP:** _(fill in)_';
  const earliest = sig.reduce((a, c) => Math.max(a, c.recommended_notice_days ?? 0), 0);
  const artifacts = new Set<string>();
  for (const c of [...sig, ...adv]) for (const a of c.required_artifacts) artifacts.add(a);

  const fmt = (cls: ScnClassification) => {
    const aff = cls.change.affected?.length ? ` Affected: ${cls.change.affected.map((a) => a.identifier).join(', ')}.` : '';
    const dn = cls.recommended_notice_days != null ? ` _(recommended notice: ${cls.recommended_notice_days} days)_` : '';
    return `- **[${cls.rule_id}]** ${cls.change.description}${aff} ${cls.rationale}${dn}`;
  };

  return [
    `# Significant Change Notification (SCN) — DRAFT`,
    ``,
    `_Generated ${report.generated_at} from run ${report.run_id}. This is a starting point —`,
    `complete the bracketed sections, attach the listed artifacts, and forward to the`,
    `authorizing agency before applying the changes._`,
    ``,
    sysLine,
    cspLine,
    `**Recommended advance notice:** ${earliest} day(s)`,
    `**Detected changes:** ${sig.length} significant, ${adv.length} advisory.`,
    ``,
    `## 1. Significant changes`,
    sig.length ? sig.map(fmt).join('\n') : '_None._',
    ``,
    `## 2. Advisory changes`,
    adv.length ? adv.map(fmt).join('\n') : '_None._',
    ``,
    `## 3. Required artifacts (consolidated)`,
    [...artifacts].sort().map((a) => `- ${a}`).join('\n') || '_None._',
    ``,
    `## 4. Acknowledgement`,
    `_Authorizing-agency reviewer: please reply to confirm receipt, or request additional`,
    `information. We will hold the change until acknowledgement is on file._`,
    ``,
  ].join('\n');
}

// ───────────────────────── Disk reader / emitter ─────────────────────────

function readJson<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, 'utf8')) as T; } catch { return null; }
}

export interface BuildScnReportOptions {
  outDir: string;
  runId: string;
  /** Override the default rules. */
  rules?: ScnRule[];
  /** Optional path to a JSON file of operator-proposed changes. */
  proposedChangesPath?: string;
  /** Optional system metadata for the draft notice. */
  systemName?: string;
  cspName?: string;
}

/** Read diff-report.json + inventory-diff.json + optional proposed file; classify; build a report. */
export function buildScnReport(opts: BuildScnReportOptions): ScnReport {
  const diffSummary = readJson<any>(resolve(opts.outDir, 'diff-report.json'));
  const inventoryDiff = readJson<InventoryDiff>(resolve(opts.outDir, 'inventory-diff.json'));
  let proposed: ScnChange[] = [];
  if (opts.proposedChangesPath) {
    const raw = readJson<any>(opts.proposedChangesPath);
    if (Array.isArray(raw)) proposed = raw as ScnChange[];
    else if (raw && Array.isArray((raw as any).changes)) proposed = (raw as any).changes as ScnChange[];
  }
  const changes = harvestChanges({ diffSummary, inventoryDiff, proposed });
  const classifications = classifyChanges(changes, opts.rules);
  const totals = {
    significant: classifications.filter((c) => c.significance === 'significant').length,
    advisory: classifications.filter((c) => c.significance === 'advisory').length,
    not_significant: classifications.filter((c) => c.significance === 'not-significant').length,
    total: classifications.length,
  };
  const generated_at = new Date().toISOString();
  // Initialize `draft_notice` empty so the in-memory report object is fully shaped
  // before draftNotice() computes the real notice text from the finalized record.
  const report: ScnReport = { run_id: opts.runId, generated_at, totals, classifications, draft_notice: '' };
  report.draft_notice = draftNotice(report, { systemName: opts.systemName, csp: opts.cspName });
  return report;
}

/** Write the report (JSON) and the draft notice (Markdown) to disk. */
export function writeScnReport(report: ScnReport, jsonPath: string, noticePath?: string): void {
  writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  if (noticePath) writeFileSync(noticePath, report.draft_notice);
}
