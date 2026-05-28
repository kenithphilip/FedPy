/**
 * OSCAL schema validation (OSC-1).
 *
 * Validates the OSCAL documents we emit (assessment-results today; ssp/poam
 * later) against NIST's official JSON Schemas — using the `ajv` we already vendor
 * and the schemas committed offline by `scripts/extract-oscal-schemas.mjs`
 * (docs/oscal/). No runtime network; aligned with our "commit data" pattern.
 *
 * Reserve shelling out to a Go OSCAL tool only if we ever need XML validation
 * (see research reports 07/11); JSON validation is fully covered here.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv, { type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OSCAL_SCHEMA_VERSION = '1.1.2';
const SCHEMA_DIR = resolve(__dirname, '..', 'docs', 'oscal');

export type OscalModel = 'assessment-results' | 'ssp' | 'poam';

export interface OscalValidationResult {
  valid: boolean;
  model: OscalModel;
  schema_found: boolean;
  /** Human-readable validation errors (capped). */
  errors: string[];
}

let _ajv: Ajv | null = null;
function ajv(): Ajv {
  if (!_ajv) {
    // NIST OSCAL schemas are draft-07 and not "strict-clean"; mirror core/schema.ts.
    _ajv = new Ajv({ allErrors: true, strict: false });
    (addFormats as unknown as (a: Ajv) => void)(_ajv);
  }
  return _ajv;
}

const _validators = new Map<OscalModel, ValidateFunction | null>();
function validator(model: OscalModel): ValidateFunction | null {
  if (_validators.has(model)) return _validators.get(model)!;
  const path = resolve(SCHEMA_DIR, `oscal_${model}_schema.v${OSCAL_SCHEMA_VERSION}.json`);
  if (!existsSync(path)) { _validators.set(model, null); return null; }
  try {
    const schema = JSON.parse(readFileSync(path, 'utf8'));
    const fn = ajv().compile(schema);
    _validators.set(model, fn);
    return fn;
  } catch {
    _validators.set(model, null);
    return null;
  }
}

/** Reset compiled-validator cache (tests). */
export function _resetOscalValidators(): void { _validators.clear(); }

/** Validate a parsed OSCAL document object against the committed NIST schema. */
export function validateOscal(doc: unknown, model: OscalModel = 'assessment-results'): OscalValidationResult {
  const fn = validator(model);
  if (!fn) {
    return {
      valid: false, model, schema_found: false,
      errors: [`OSCAL ${model} schema (v${OSCAL_SCHEMA_VERSION}) not found in ${SCHEMA_DIR}. Run \`node scripts/extract-oscal-schemas.mjs\`.`],
    };
  }
  const ok = fn(doc) as boolean;
  const errors = ok ? [] : (fn.errors ?? []).slice(0, 50).map((e) => {
    const where = e.instancePath || '(root)';
    const extra = e.params && Object.keys(e.params).length ? ` ${JSON.stringify(e.params)}` : '';
    return `${where} ${e.message ?? 'invalid'}${extra}`;
  });
  return { valid: ok, model, schema_found: true, errors };
}

/** Validate an OSCAL document file on disk. */
export function validateOscalFile(path: string, model: OscalModel = 'assessment-results'): OscalValidationResult {
  if (!existsSync(path)) return { valid: false, model, schema_found: true, errors: [`file not found: ${path}`] };
  let doc: unknown;
  try { doc = JSON.parse(readFileSync(path, 'utf8')); }
  catch (e: any) { return { valid: false, model, schema_found: true, errors: [`invalid JSON: ${e?.message ?? e}`] }; }
  return validateOscal(doc, model);
}
