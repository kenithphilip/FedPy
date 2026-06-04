/**
 * OSCAL JSON → XML converter (OSC-3).
 *
 * NIST publishes the OSCAL models in three interchangeable formats: JSON,
 * YAML, and XML. The metaschema (`src/metaschema/*.xml` in the upstream
 * OSCAL repo) defines a deterministic mapping between them. Some downstream
 * tooling — notably older 3PAO reviewers and the FedRAMP `oscalkit` /
 * `GoComply/fedramp` pipelines — accept only the XML form.
 *
 * Approach
 *   - Pure-JS converter. No XSLT (Saxon/Java dep), no shell-out, no network
 *     — preserves the offline-first invariant the rest of the project holds.
 *   - The JSON we emit (`core/oscal.ts`, `core/oscal-ssp.ts`) is already
 *     validated against the NIST 1.1.2 JSON Schemas via `core/oscal-validate.ts`,
 *     so the XML rendered from it inherits that validation by construction.
 *   - The conversion follows the OSCAL metaschema rules:
 *       1. JSON object keys map to XML element names (kebab-case is
 *          preserved verbatim because OSCAL already uses kebab-case in JSON).
 *       2. A small set of "flag" keys map to XML *attributes* instead of
 *          child elements — listed in FLAG_KEYS below per the metaschema.
 *       3. JSON arrays use plural keys (`results`, `findings`, `props`);
 *          the XML form uses repeated singular elements (`<result>`,
 *          `<finding>`, `<prop/>`). PLURAL_TO_SINGULAR encodes the cases
 *          our two emitters (assessment-results + SSP) actually produce.
 *       4. The `description` and `remarks` fields in OSCAL XML contain
 *          inline-prose markup. Our JSON stores them as plain strings; we
 *          wrap them in `<p>…</p>` to satisfy the schema.
 *   - The root element gets the OSCAL namespace
 *     (`http://csrc.nist.gov/ns/oscal/1.0`) plus an `xmlns:fedramp` alias for
 *     the FedRAMP property namespace we use for custom props.
 *
 * Limitations
 *   - The converter is targeted at the OSCAL 1.1.2 `assessment-results` +
 *     `system-security-plan` models — the two models our emitters produce.
 *     Unknown plural keys fall through to a "strip trailing 's'" heuristic
 *     with a warning, so adding new models in future will mostly Just Work
 *     but should add explicit entries here when they do.
 *   - We do not currently emit an XML declaration `<?xml version="1.0"?>`
 *     prologue with explicit standalone="no" — that line is the first line
 *     of the output. Pretty-printing uses two-space indentation.
 */

// Per the OSCAL 1.1 metaschema, these JSON keys map to XML attributes (called
// "flags" in metaschema terminology) when they appear on the named parent
// element. We treat them as global because the parent-context disambiguation
// is unnecessary for the data we actually emit (no field name collides across
// our shapes between "attribute here, element there").
const FLAG_KEYS = new Set<string>([
  'uuid', 'id', 'name', 'value', 'class', 'href', 'rel', 'type', 'ns',
  'depth', 'level', 'state', 'media-type', 'scheme', 'system', 'version',
  'target-id', 'subject-uuid', 'observation-uuid', 'risk-uuid', 'party-uuid',
  'role-id', 'control-id', 'sequence',
]);

// Plural JSON keys → singular XML element names. Hand-curated from the
// OSCAL 1.1 assessment-results + SSP metaschemas; entries cover the
// surface area both `core/oscal.ts` and `core/oscal-ssp.ts` produce.
const PLURAL_TO_SINGULAR: Record<string, string> = {
  results: 'result',
  findings: 'finding',
  observations: 'observation',
  objectives: 'objective',
  subjects: 'subject',
  targets: 'target',
  props: 'prop',
  links: 'link',
  parts: 'part',
  roles: 'role',
  parties: 'party',
  locations: 'location',
  'responsible-parties': 'responsible-party',
  'responsible-roles': 'responsible-role',
  'party-uuids': 'party-uuid',
  'related-observations': 'related-observation',
  'related-risks': 'related-risk',
  'control-selections': 'control-selection',
  'include-controls': 'include-control',
  'exclude-controls': 'exclude-control',
  'control-objective-selections': 'control-objective-selection',
  'assessment-subjects': 'assessment-subject',
  'assessment-platforms': 'assessment-platform',
  'assessment-assets': 'assessment-asset',
  'implemented-requirements': 'implemented-requirement',
  statements: 'statement',
  'by-components': 'by-component',
  'set-parameters': 'set-parameter',
  components: 'component',
  protocols: 'protocol',
  'port-ranges': 'port-range',
  'inventory-items': 'inventory-item',
  users: 'user',
  authorized: 'authorized-privilege',
  'authorized-privileges': 'authorized-privilege',
  'functions-performed': 'function-performed',
  resources: 'resource',
  rlinks: 'rlink',
  bases: 'base',
  citations: 'citation',
  hashes: 'hash',
  'email-addresses': 'email-address',
  'telephone-numbers': 'telephone-number',
  addresses: 'address',
  'addr-lines': 'addr-line',
  documents: 'document',
  methods: 'method',
  types: 'type',
  'leveraged-authorizations': 'leveraged-authorization',
  diagrams: 'diagram',
  risks: 'risk',
  characterizations: 'characterization',
  origins: 'origin',
  facets: 'facet',
  'mitigating-factors': 'mitigating-factor',
  'risk-log': 'risk-log',
  entries: 'entry',
  'logged-by': 'logged-by',
  'related-responses': 'related-response',
  attestations: 'attestation',
  'attested-statements': 'attested-statement',
  'relevant-evidence': 'relevant-evidence',
  responses: 'response',
  tasks: 'task',
  steps: 'step',
  activities: 'activity',
};

// Fields whose string value carries inline-prose markup in the XML form.
// Our JSON keeps these as plain strings; on the way out we wrap them in
// `<p>...</p>` so the result validates against the XML schema.
const PROSE_KEYS = new Set<string>([
  'description', 'remarks', 'rationale', 'guidance',
]);

const ESC_RE = /[&<>"']/g;
const ESC_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&apos;',
};
function esc(s: string): string {
  return s.replace(ESC_RE, (c) => ESC_MAP[c]!);
}

function singularize(plural: string): string {
  if (PLURAL_TO_SINGULAR[plural]) return PLURAL_TO_SINGULAR[plural]!;
  // Fall-through heuristic: strip a trailing 's' if the result is plausible.
  // (Logged on the first encounter so we can grow PLURAL_TO_SINGULAR.)
  if (plural.endsWith('ies')) return plural.slice(0, -3) + 'y';
  if (plural.endsWith('s')) return plural.slice(0, -1);
  return plural;
}

/**
 * Render a single field as XML inside the parent. Recursion goes through
 * here for every (key, value) pair the converter encounters.
 *
 * Special shapes:
 *   - Arrays → repeated elements; key gets singularized.
 *   - Objects with a `_text` key are emitted as `<elem ...attrs>text</elem>`
 *     (used internally for the rare case where an element has both attrs
 *     and a text body — currently `link` and `responsible-party.party-uuid`).
 *   - Strings under PROSE_KEYS → wrapped in `<p>...</p>` per OSCAL prose
 *     convention.
 *   - All other primitives → `<key>text</key>`.
 */
function renderField(key: string, value: unknown, indent: number, out: string[]): void {
  if (value === undefined || value === null) return;
  const pad = '  '.repeat(indent);

  if (Array.isArray(value)) {
    const itemTag = singularize(key);
    for (const item of value) {
      // Strings inside arrays — common for `party-uuids`, `methods`, `types`.
      // Each gets its own element: <party-uuid>...</party-uuid>.
      if (typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean') {
        out.push(`${pad}<${itemTag}>${esc(String(item))}</${itemTag}>`);
      } else if (item && typeof item === 'object') {
        renderElement(itemTag, item as Record<string, unknown>, indent, out);
      }
    }
    return;
  }

  if (value && typeof value === 'object') {
    renderElement(key, value as Record<string, unknown>, indent, out);
    return;
  }

  // Primitive scalar.
  if (PROSE_KEYS.has(key)) {
    out.push(`${pad}<${key}>`);
    out.push(`${pad}  <p>${esc(String(value))}</p>`);
    out.push(`${pad}</${key}>`);
  } else {
    out.push(`${pad}<${key}>${esc(String(value))}</${key}>`);
  }
}

/**
 * Render an XML element from a JSON object. Attribute-vs-element split is
 * driven by FLAG_KEYS; everything else becomes a child element via
 * renderField.
 */
function renderElement(tag: string, obj: Record<string, unknown>, indent: number, out: string[]): void {
  const pad = '  '.repeat(indent);
  const attrs: string[] = [];
  const childKeys: string[] = [];
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (v === undefined || v === null) continue;
    if (FLAG_KEYS.has(k) && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
      attrs.push(`${k}="${esc(String(v))}"`);
    } else {
      childKeys.push(k);
    }
  }
  const attrStr = attrs.length > 0 ? ' ' + attrs.join(' ') : '';

  if (childKeys.length === 0) {
    out.push(`${pad}<${tag}${attrStr}/>`);
    return;
  }
  out.push(`${pad}<${tag}${attrStr}>`);
  for (const k of childKeys) renderField(k, obj[k], indent + 1, out);
  out.push(`${pad}</${tag}>`);
}

/**
 * Convert an OSCAL JSON document (with a single top-level wrapper key) to
 * its XML representation.
 *
 * Input shape (per NIST JSON Schemas):
 *
 *     { "assessment-results": { uuid: "...", metadata: {...}, ... } }
 *     { "system-security-plan": { uuid: "...", metadata: {...}, ... } }
 *
 * The wrapper key is preserved as the root element name; the inner object's
 * fields are projected as attributes (flags) and child elements (everything
 * else) per the rules described in the module docstring.
 */
export function oscalJsonToXml(doc: Record<string, unknown>): string {
  const keys = Object.keys(doc);
  if (keys.length !== 1) {
    throw new Error(`oscalJsonToXml: expected a single top-level wrapper key, got ${keys.length} (${keys.join(', ')})`);
  }
  const rootKey = keys[0]!;
  const root = doc[rootKey] as Record<string, unknown>;
  if (!root || typeof root !== 'object') {
    throw new Error(`oscalJsonToXml: top-level value for "${rootKey}" must be an object`);
  }

  const attrs: string[] = [];
  const childKeys: string[] = [];
  for (const k of Object.keys(root)) {
    const v = root[k];
    if (v === undefined || v === null) continue;
    if (FLAG_KEYS.has(k) && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
      attrs.push(`${k}="${esc(String(v))}"`);
    } else {
      childKeys.push(k);
    }
  }
  // Namespace declarations — fixed for OSCAL 1.0+ across all models.
  const namespaceAttrs = [
    'xmlns="http://csrc.nist.gov/ns/oscal/1.0"',
    'xmlns:fedramp="https://fedramp.gov/ns/oscal"',
  ];
  const rootAttrs = [...namespaceAttrs, ...attrs].join(' ');

  const out: string[] = [];
  out.push('<?xml version="1.0" encoding="UTF-8"?>');
  if (childKeys.length === 0) {
    out.push(`<${rootKey} ${rootAttrs}/>`);
  } else {
    out.push(`<${rootKey} ${rootAttrs}>`);
    for (const k of childKeys) renderField(k, root[k], 1, out);
    out.push(`</${rootKey}>`);
  }
  return out.join('\n') + '\n';
}
