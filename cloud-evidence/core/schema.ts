/**
 * Runtime JSON Schema for an EvidenceFile (the per-KSI output written by the
 * orchestrator).
 *
 * Why this exists:
 *   1. Catch collector bugs (e.g. a missing `current_state.summary`) before
 *      they propagate downstream into Paramify push, tracker push, LLM PR
 *      generation, or audit packages.
 *   2. Give third-party consumers (Paramify, OSCAL converters, GRC ingest
 *      tools) a single authoritative schema reference.
 *
 * The schema mirrors `core/envelope.ts` but is intentionally LOOSE in places
 * where collectors include arbitrary raw SDK data (`current_state.observations`,
 * `RawEvidence.data`, `AffectedResource.attributes`, `tags`). For required
 * fields and enums, we are strict.
 */
import Ajv, { type ErrorObject, type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import type { EvidenceFile } from './envelope.ts';

const SEVERITY_VALUES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const PROVIDER_VALUES = ['aws', 'gcp', 'k8s'] as const;
const SCOPE_VALUES = ['CLOUD', 'HYBRID', 'PROCESS', 'INHERITED'] as const;
const IMPACT_VALUES = ['none', 'low', 'medium', 'high'] as const;
const EFFORT_VALUES = ['minutes', 'hours', 'days', 'weeks', 'months'] as const;
const MECHANISM_VALUES = ['terraform', 'cloudformation', 'console', 'cli', 'process', 'external-tool'] as const;
const RELATIONSHIP_VALUES = ['shares-remediation', 'precedes', 'follows', 'conflicts-with', 'depends-on'] as const;
const CONFIDENCE_VALUES = ['direct', 'inferred'] as const;

const referenceSchema = {
  type: 'object',
  required: ['title', 'url'],
  additionalProperties: false,
  properties: {
    title: { type: 'string', minLength: 1 },
    url: { type: 'string', format: 'uri' },
  },
} as const;

const affectedResourceSchema = {
  type: 'object',
  required: ['type', 'identifier'],
  additionalProperties: false,
  properties: {
    type: { type: 'string', minLength: 1 },
    identifier: { type: 'string', minLength: 1 },
    name: { type: 'string' },
    attributes: { type: 'object', additionalProperties: true },
    tags: { type: 'object', additionalProperties: { type: 'string' } },
  },
} as const;

const remediationOptionSchema = {
  type: 'object',
  required: ['approach', 'mechanism', 'steps'],
  additionalProperties: false,
  properties: {
    approach: { type: 'string', minLength: 1 },
    mechanism: { type: 'string', enum: [...MECHANISM_VALUES] },
    steps: { type: 'array', items: { type: 'string', minLength: 1 }, minItems: 1 },
    example_code: { type: 'string' },
    side_effects: { type: 'array', items: { type: 'string' } },
    prerequisites: { type: 'array', items: { type: 'string' } },
    references: { type: 'array', items: referenceSchema },
    cost_impact: {
      type: 'object',
      required: ['level', 'notes'],
      additionalProperties: false,
      properties: { level: { enum: [...IMPACT_VALUES] }, notes: { type: 'string' } },
    },
    availability_impact: {
      type: 'object',
      required: ['level', 'notes'],
      additionalProperties: false,
      properties: { level: { enum: [...IMPACT_VALUES] }, notes: { type: 'string' } },
    },
    customer_visible: {
      type: 'object',
      required: ['level', 'notes'],
      additionalProperties: false,
      properties: { level: { enum: [...IMPACT_VALUES] }, notes: { type: 'string' } },
    },
    effort_estimate: {
      type: 'object',
      required: ['magnitude', 'notes'],
      additionalProperties: false,
      properties: { magnitude: { enum: [...EFFORT_VALUES] }, notes: { type: 'string' } },
    },
    owner_team: { type: 'string' },
  },
} as const;

const alternativeSatisfierSchema = {
  type: 'object',
  required: ['via', 'description', 'evidence_required', 'detected'],
  additionalProperties: false,
  properties: {
    via: { type: 'string', minLength: 1 },
    description: { type: 'string', minLength: 1 },
    evidence_required: { type: 'array', items: { type: 'string' } },
    detected: { type: 'boolean' },
    detection_signals: { type: 'array', items: { type: 'string' } },
  },
} as const;

const findingSchema = {
  type: 'object',
  required: ['rule', 'passed', 'severity', 'current_state', 'target_state'],
  additionalProperties: false,
  properties: {
    rule: { type: 'string', minLength: 1 },
    passed: { type: 'boolean' },
    severity: { enum: [...SEVERITY_VALUES] },
    current_state: {
      type: 'object',
      required: ['summary', 'observations'],
      additionalProperties: false,
      properties: {
        summary: { type: 'string', minLength: 1 },
        observations: {}, // arbitrary raw data
      },
    },
    target_state: {
      type: 'object',
      required: ['summary', 'rationale'],
      additionalProperties: false,
      properties: {
        summary: { type: 'string', minLength: 1 },
        rationale: { type: 'string', minLength: 1 },
      },
    },
    gap: {
      type: 'object',
      required: ['description', 'affected_resources'],
      additionalProperties: false,
      properties: {
        description: { type: 'string', minLength: 1 },
        affected_resources: { type: 'array', items: affectedResourceSchema },
      },
    },
    remediation: {
      type: 'object',
      required: ['summary', 'options'],
      additionalProperties: false,
      properties: {
        summary: { type: 'string', minLength: 1 },
        options: { type: 'array', items: remediationOptionSchema, minItems: 1 },
      },
    },
    alternative_satisfiers: { type: 'array', items: alternativeSatisfierSchema },
    nist_controls: { type: 'array', items: { type: 'string' } },
    references: { type: 'array', items: referenceSchema },
    cross_ksi_dependencies: {
      type: 'array',
      items: {
        type: 'object',
        required: ['ksi_id', 'relationship', 'note'],
        additionalProperties: false,
        properties: {
          ksi_id: { type: 'string' },
          relationship: { enum: [...RELATIONSHIP_VALUES] },
          note: { type: 'string' },
        },
      },
    },
    compliance_blockers: { type: 'array', items: { type: 'string' } },
    note: { type: 'string' },
    applicable_key_word: { enum: ['MUST', 'SHOULD', 'MAY'] },
  },
  // When passed=false, require gap + remediation. Ajv supports this via `if/then`.
  if: { properties: { passed: { const: false } } },
  then: { required: ['rule', 'passed', 'severity', 'current_state', 'target_state', 'gap', 'remediation'] },
} as const;

const rawEvidenceSchema = {
  type: 'object',
  required: ['source', 'captured_at', 'data'],
  additionalProperties: false,
  properties: {
    source: { type: 'string', minLength: 1 },
    captured_at: { type: 'string', format: 'date-time' },
    data: {}, // arbitrary
  },
} as const;

const thirdPartyToolSchema = {
  type: 'object',
  required: ['name', 'category', 'confidence', 'detection_signals', 'satisfies_ksis'],
  additionalProperties: false,
  properties: {
    name: { type: 'string', minLength: 1 },
    category: { type: 'string' },
    confidence: { enum: [...CONFIDENCE_VALUES] },
    detection_signals: { type: 'array', items: { type: 'string' } },
    satisfies_ksis: { type: 'array', items: { type: 'string' } },
  },
} as const;

const providerBlockSchema = {
  type: 'object',
  required: ['provider', 'evidence', 'findings'],
  additionalProperties: false,
  properties: {
    provider: { enum: [...PROVIDER_VALUES] },
    account_id: { type: ['string', 'null'] },
    project_id: { type: ['string', 'null'] },
    region_set: { type: 'array', items: { type: 'string' } },
    evidence: { type: 'array', items: rawEvidenceSchema },
    findings: { type: 'array', items: findingSchema },
    warnings: { type: 'array', items: { type: 'string' } },
    ksi_level_alternatives: { type: 'array', items: alternativeSatisfierSchema },
    third_party_tools_detected: { type: 'array', items: thirdPartyToolSchema },
  },
} as const;

const rollupSchema = {
  type: 'object',
  required: ['pass', 'passing_findings', 'failing_findings', 'warnings', 'missing_evidence', 'alternatives_in_play'],
  additionalProperties: false,
  properties: {
    pass: { type: 'boolean' },
    passing_findings: { type: 'integer', minimum: 0 },
    failing_findings: { type: 'integer', minimum: 0 },
    warnings: { type: 'array', items: { type: 'string' } },
    missing_evidence: { type: 'array', items: { type: 'string' } },
    alternatives_in_play: { type: 'integer', minimum: 0 },
  },
} as const;

export const evidenceFileSchema = {
  $id: 'https://fedramp-20x/cloud-evidence/EvidenceFile.json',
  type: 'object',
  required: ['ksi_id', 'ksi_name', 'ksi_statement', 'scope', 'frmr_version', 'run_id', 'collected_at', 'providers', 'rollup'],
  additionalProperties: false,
  properties: {
    ksi_id: { type: 'string', minLength: 1 },
    ksi_name: { type: 'string', minLength: 1 },
    ksi_statement: { type: 'string', minLength: 1 },
    scope: { enum: [...SCOPE_VALUES] },
    frmr_version: { type: 'string' },
    run_id: { type: 'string', minLength: 1 },
    collected_at: { type: 'string', format: 'date-time' },
    providers: { type: 'array', items: providerBlockSchema },
    rollup: rollupSchema,
    process_artifacts_required: { type: 'array', items: { type: 'string' } },
    nist_controls: { type: 'array', items: { type: 'string' } },
    related_ksis: {
      type: 'array',
      items: {
        type: 'object',
        required: ['ksi_id', 'relationship', 'note'],
        additionalProperties: false,
        properties: {
          ksi_id: { type: 'string' },
          relationship: { enum: ['shares-remediation', 'precedes', 'follows', 'depends-on'] },
          note: { type: 'string' },
        },
      },
    },
    summary_for_llm: { type: 'string' },
    // ── Impact-tier / requirement-taxonomy metadata (full-level coverage) ──
    category: { enum: ['ksi-indicator', 'frr-requirement'] },
    family: { type: 'string' },
    impact_level: { enum: ['low', 'moderate', 'high'] },
    applicable_key_word: { enum: ['MUST', 'SHOULD', 'MAY'] },
    level_source: { enum: ['20x-machine-readable', 'derived-rev5', 'derived-rev5-pending', 'not-applicable'] },
    actor_scope: { enum: ['provider', 'fedramp', 'agency', '3pao', 'unknown'] },
    awareness_only: { type: 'boolean' },
  },
} as const;

// ---- Validator instance ----

let _ajv: Ajv | null = null;
let _validate: ValidateFunction<EvidenceFile> | null = null;

function getValidator(): ValidateFunction<EvidenceFile> {
  if (_validate) return _validate;
  // ajv-formats default export is the function we call; types are looser than reality.
  _ajv = new Ajv({ allErrors: true, strict: false });
  (addFormats as unknown as (a: Ajv) => void)(_ajv);
  _validate = _ajv.compile<EvidenceFile>(evidenceFileSchema as any);
  return _validate;
}

export interface ValidationResult {
  valid: boolean;
  errors: ErrorObject[];
}

/**
 * Validate an EvidenceFile-shaped object. Returns structured errors instead of
 * throwing — the orchestrator decides whether to fail-hard or warn.
 */
export function validateEvidenceFile(doc: unknown): ValidationResult {
  const v = getValidator();
  const valid = v(doc);
  return { valid: Boolean(valid), errors: v.errors ?? [] };
}

/** Format ajv errors into a human-readable multi-line string. */
export function formatErrors(errors: ErrorObject[]): string {
  if (errors.length === 0) return '(no errors)';
  return errors
    .map((e) => {
      const path = e.instancePath || '/';
      const params = JSON.stringify(e.params);
      return `  ${path}  ${e.message}  ${params}`;
    })
    .join('\n');
}
