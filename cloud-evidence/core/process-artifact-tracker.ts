/**
 * Process-artifact tracker.
 *
 * ~99 of the FedRAMP 20x requirements are governance / reporting / comms
 * obligations that cannot be proven by a read-only cloud API call (e.g.
 * "submit quarterly reviews", "maintain a monitored security inbox",
 * "notify FedRAMP of significant changes within N business days").
 *
 * For those we still want first-class, signed, schema-valid, OSCAL-mapped,
 * LLM-readable evidence — just sourced from a tracked ARTIFACT + ATTESTATION
 * instead of a cloud SDK call. This module turns a RequirementEntry into a
 * standard `scope: PROCESS` EvidenceFile:
 *
 *   - If the operator has recorded an attestation (artifact URL/hash, who, when,
 *     optional expiry) for the requirement → PASS (info).
 *   - Otherwise → a gap describing the artifact the reviewer must attach, with
 *     process remediation steps and detected alternative satisfiers (GRC
 *     platforms, IdPs, scanners, etc.).
 *   - If an SLA/cadence is configured (anchor event + window) → the deadline is
 *     evaluated with core/bizdays.ts and an overdue obligation becomes a gap.
 *
 * The attestation register is operator-maintained data (read-only here); the
 * tracker never mutates anything.
 */
import type {
  EvidenceFile, ProviderBlock, ProviderName, ImpactTier, ThirdPartyToolMatch,
  AlternativeSatisfier, Finding,
} from './envelope.ts';
import { finding, severityForKeyWord } from './findings.ts';
import { appliesAtLevel, actorScopeOf, type RequirementEntry } from './requirements-registry.ts';
import { deadlineStatus } from './bizdays.ts';

/** Operator-recorded proof that a process requirement is met. */
export interface AttestationRecord {
  requirement_id: string;
  /** URL to the artifact (policy doc, report, runbook, ticket, dashboard). */
  artifact_url?: string;
  /** Optional content hash for integrity. */
  artifact_sha256?: string;
  /** Who attested. */
  attested_by?: string;
  /** ISO timestamp of the attestation. */
  attested_at?: string;
  /** ISO timestamp after which the attestation is stale and must be renewed. */
  expires_at?: string;
  notes?: string;
}

/** Per-requirement guidance the family modules supply (specific steps/artifacts/satisfiers). */
export interface RequirementPlaybook {
  /** Specific artifacts the reviewer must attach (overrides the generic list). */
  artifacts_required?: string[];
  /** Ordered, practical remediation steps that satisfy the FedRAMP requirement. */
  remediation_steps?: string[];
  /** Requirement-specific alternative satisfiers (vendor/process). */
  alternative_satisfiers?: AlternativeSatisfier[];
  /** Override / supplement the NIST controls. */
  nist_controls?: string[];
  /** SLA: deadline = anchor + window. Anchor comes from the attestation or ctx. */
  sla?: { anchorIso?: string; businessDays?: number; calendarDays?: number; cadence?: string };
  /** Reference doc URLs. */
  references?: Array<{ title: string; url: string }>;
}

export interface ProcessTrackerContext {
  tier: ImpactTier;
  /** Run id for the envelope. */
  runId: string;
  frmrVersion: string;
  /** Provider label for the (provider-neutral) ProviderBlock; defaults to 'aws'. */
  provider?: ProviderName;
  /** Operator attestation register, keyed by requirement id. */
  attestations?: Record<string, AttestationRecord>;
  /** Third-party tools detected elsewhere in the run (for alternative satisfiers). */
  detectedTools?: ThirdPartyToolMatch[];
  /** Per-requirement playbooks, keyed by requirement id. */
  playbooks?: Record<string, RequirementPlaybook>;
  /** "now" override for deterministic tests. */
  nowIso?: string;
}

function attestationFresh(att: AttestationRecord | undefined, nowIso: string): boolean {
  if (!att || !att.artifact_url) return false;
  if (att.expires_at) {
    const exp = new Date(att.expires_at).getTime();
    if (!Number.isNaN(exp) && exp < new Date(nowIso).getTime()) return false; // stale
  }
  return true;
}

/** Build alternative satisfiers from detected third-party tools relevant to this family. */
function alternativeSatisfiersFor(
  req: RequirementEntry,
  playbook: RequirementPlaybook | undefined,
  detected: ThirdPartyToolMatch[],
): AlternativeSatisfier[] {
  const out: AlternativeSatisfier[] = [...(playbook?.alternative_satisfiers ?? [])];
  // Roll up any detected tool that claims to satisfy this requirement's family/id.
  for (const tool of detected) {
    const claims = tool.satisfies_ksis ?? [];
    if (claims.includes(req.id) || claims.includes(req.family) || claims.some((c) => req.id.startsWith(c))) {
      out.push({
        via: `${tool.name} (${tool.category})`,
        description: `${tool.name} was detected in this environment and is commonly used to satisfy ${req.family} obligations.`,
        evidence_required: [`${tool.name} tenant/account + export covering ${req.id}`],
        detected: true,
        detection_signals: tool.detection_signals,
      });
    }
  }
  // Always offer a generic GRC-platform path (continuous-compliance vendors).
  if (!out.some((a) => /vanta|drata|secureframe|paramify|grc/i.test(a.via))) {
    out.push({
      via: 'Continuous-compliance / GRC platform (Vanta, Drata, Secureframe, Paramify)',
      description: 'A GRC platform can own this process obligation and produce the artifact + attestation history externally.',
      evidence_required: ['Platform tenant + the control/test mapped to this requirement', 'Export showing the obligation is met on cadence'],
      detected: false,
      detection_signals: [],
    });
  }
  return out;
}

/**
 * Produce a PROCESS-scope EvidenceFile for one requirement.
 */
export function buildProcessArtifactEvidence(req: RequirementEntry, ctx: ProcessTrackerContext): EvidenceFile {
  const nowIso = ctx.nowIso ?? new Date().toISOString();
  const ap = appliesAtLevel(req, ctx.tier);
  const playbook = ctx.playbooks?.[req.id];
  const att = ctx.attestations?.[req.id];
  const statement = ap.statement || req.statement || req.name;
  const kw = ap.key_word;
  const provider: ProviderName = ctx.provider ?? 'aws';

  const artifactsRequired = playbook?.artifacts_required ?? [
    `Documented artifact evidencing "${req.name}" (policy / report / runbook / record)`,
    'Attestation: who confirmed it, when, and a link to the artifact',
  ];
  const altSatisfiers = alternativeSatisfiersFor(req, playbook, ctx.detectedTools ?? []);
  const nistControls = playbook?.nist_controls ?? req.controls ?? [];

  // ── SLA / cadence evaluation ────────────────────────────────────────────
  let slaNote: string | undefined;
  let slaOverdue = false;
  const sla = playbook?.sla;
  const anchorIso = sla?.anchorIso ?? att?.attested_at;
  if (sla && anchorIso && (sla.businessDays != null || sla.calendarDays != null)) {
    try {
      const st = deadlineStatus(anchorIso, { businessDays: sla.businessDays, calendarDays: sla.calendarDays }, nowIso);
      slaOverdue = st.overdue;
      slaNote = st.overdue
        ? `SLA BREACH: due ${st.due} (${st.basis}); ${st.days_past_due} ${st.basis} overdue.`
        : `Within SLA: due ${st.due}; ${-st.days_past_due} ${st.basis} remaining.`;
    } catch {
      slaNote = `SLA configured but anchor date "${anchorIso}" could not be parsed.`;
    }
  }

  const actorScope = actorScopeOf(req);
  const awarenessOnly = actorScope !== 'provider';
  const hasAttestation = attestationFresh(att, nowIso);
  // Awareness items obligate FedRAMP/agency/3PAO, not the provider — the CSP can't
  // "fail" them, so they always pass as informational awareness records.
  const passed = awarenessOnly ? true : (hasAttestation && !slaOverdue);

  const observations = {
    requirement_id: req.id,
    family: req.family,
    impact_tier: ctx.tier,
    applicable_key_word: kw,
    level_source: ap.source,
    attestation: att ?? null,
    attestation_fresh: hasAttestation,
    sla: slaNote ?? null,
    detected_tools: (ctx.detectedTools ?? []).map((t) => t.name),
  };

  const f: Finding = finding({
    rule: `frmr.process.${req.id.toLowerCase()}`,
    passed,
    severity: passed ? 'info' : severityForKeyWord(kw, 'medium'),
    applicable_key_word: kw ?? undefined,
    current: {
      summary: awarenessOnly
        ? `${req.id} obligates ${actorScope.toUpperCase()}, not the provider. Tracked for awareness; not counted in the provider's pass/fail.`
        : passed
          ? `Attested: ${att?.artifact_url} (by ${att?.attested_by ?? 'unknown'} on ${att?.attested_at ?? 'unknown'}).${slaNote ? ' ' + slaNote : ''}`
          : hasAttestation
            ? `Attestation present but ${slaNote ?? 'SLA breached'}.`
            : `No attestation recorded for ${req.id}. This is a process requirement — the reviewer must attach the artifact + attestation.`,
      observations,
    },
    target: {
      summary: statement,
      rationale: `FedRAMP 20x ${req.family} (${req.id}); obligation ${kw ?? 'MUST'} at ${ctx.tier}. ` +
        (ap.source === 'derived-rev5' ? 'High applicability DERIVED from NIST 800-53 Rev5 baseline. ' : '') +
        'Process/governance requirement — proven by artifact + attestation, not a cloud API.',
    },
    gap: passed ? undefined : {
      description: slaOverdue
        ? `Obligation is overdue. ${slaNote}`
        : `No fresh artifact + attestation recorded for ${req.id}.`,
      affected_resources: [{
        type: 'fedramp_process_requirement',
        identifier: req.id,
        name: req.name,
        attributes: { family: req.family, tier: ctx.tier, key_word: kw },
      }],
    },
    remediation: passed ? undefined : {
      summary: `Attach the artifact + record an attestation for ${req.id} (or wire an alternative satisfier).`,
      options: [{
        approach: `Produce/locate the artifact for "${req.name}" and record an attestation in the register.`,
        mechanism: 'process',
        owner_team: 'Compliance',
        steps: playbook?.remediation_steps ?? [
          `Identify or create the artifact that evidences: ${statement}`,
          'Have the accountable owner review + sign off (name + date + artifact link).',
          'Record it in the attestation register (requirement_id, artifact_url, attested_by, attested_at, expires_at).',
          'Re-run cloud-evidence to confirm the requirement clears.',
        ],
        cost_impact: { level: 'none', notes: 'Process effort only.' },
        availability_impact: { level: 'none', notes: 'No system change.' },
        customer_visible: { level: 'none', notes: 'Internal compliance artifact.' },
        effort_estimate: { magnitude: 'hours', notes: 'Per requirement; recurring for cadence items.' },
      }],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: nistControls,
    references: playbook?.references ?? (req.reference_url ? [{ title: req.reference ?? req.family, url: req.reference_url }] : undefined),
    note: awarenessOnly
      ? `Awareness item: this requirement obligates ${actorScope.toUpperCase()}. The provider should be aware of and support it but cannot satisfy it directly.`
      : ap.source === 'derived-rev5-pending'
        ? 'High applicability could not be derived (no NIST controls[] to anchor); evaluated as not-applicable at High.'
        : undefined,
  });

  const block: ProviderBlock = {
    provider,
    account_id: null,
    region_set: [],
    evidence: [{ source: `process.${req.id}`, captured_at: nowIso, data: observations }],
    findings: [f],
    warnings: [],
  };

  return {
    ksi_id: req.id,
    ksi_name: req.name,
    ksi_statement: statement,
    scope: 'PROCESS',
    frmr_version: ctx.frmrVersion,
    run_id: ctx.runId,
    collected_at: nowIso,
    providers: [block],
    rollup: {
      pass: passed,
      passing_findings: passed ? 1 : 0,
      failing_findings: passed ? 0 : 1,
      warnings: [],
      missing_evidence: hasAttestation ? [] : artifactsRequired,
      alternatives_in_play: altSatisfiers.filter((a) => a.detected).length,
    },
    process_artifacts_required: artifactsRequired,
    nist_controls: nistControls,
    summary_for_llm: `${req.id} (${req.family}) is a ${ctx.tier}-tier process requirement [${kw ?? 'MUST'}]. ` +
      (passed ? 'Satisfied via recorded attestation.' : 'NOT yet attested — reviewer must attach the artifact or wire an alternative satisfier.'),
    category: req.category,
    family: req.family,
    impact_level: ctx.tier,
    applicable_key_word: kw ?? undefined,
    level_source: ap.source,
    actor_scope: actorScope,
    awareness_only: awarenessOnly,
  };
}
