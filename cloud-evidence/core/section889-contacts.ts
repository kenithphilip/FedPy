/**
 * Typed loader + validator for `section889-contacts.yaml` (LOOP-W.W3).
 *
 * The operator commits this file mapping each federal contract the CSO performs
 * under to the Contracting Officer who receives a FAR 52.204-25(d) report (or,
 * for DoD primes, the DIBNet endpoint). Per cloud-evidence/CLAUDE.md REO Rule 4,
 * operator-supplied configuration is real data: a missing or malformed required
 * value throws a typed `Section889ContactsError` naming the field — the system
 * never substitutes a default that masquerades as a real Contracting Officer.
 *
 * Email syntax is validated to RFC 5322's common subset offline (no network MX
 * lookup — that would couple report composition to DNS availability and is out
 * of scope for this pure loader; the operator validates deliverability).
 */
import { readFileSync, existsSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

/** Thrown when the contacts file is missing/malformed or a required field is absent. */
export class Section889ContactsError extends Error {
  readonly field: string;
  constructor(field: string, message: string) {
    super(message);
    this.name = 'Section889ContactsError';
    this.field = field;
  }
}

export type Section889EndpointType = 'civilian-co-email' | 'dod-dibnet';
export const DIBNET_URL = 'https://dibnet.dod.mil/';

export interface Section889Contact {
  contractNumber: string;
  agency: string | null;
  endpointType: Section889EndpointType;
  contractingOfficerEmail: string | null;
  /** Set when the CSP is a subcontractor — the prime the report routes up to. */
  primeContractorUei: string | null;
  cageCode: string | null;
}

export interface Section889Contacts {
  schemaVersion: string;
  contracts: Section889Contact[];
}

/** Common RFC 5322 subset — enough to reject typos without a full grammar. */
const EMAIL_RE = /^[^\s@"']+@[^\s@".']+\.[^\s@"']{2,}$/;
const FAR_CONTRACT_RE = /^[A-Za-z0-9][A-Za-z0-9-]{4,}$/;

function asString(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  return t === '' ? null : t;
}

/** Build typed contacts from a parsed YAML object. Throws on malformed rows. */
export function normalizeSection889Contacts(raw: unknown): Section889Contacts {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, any>;
  const rows = Array.isArray(obj.contracts) ? obj.contracts : [];
  if (rows.length === 0) {
    throw new Section889ContactsError('contracts', 'section889-contacts.yaml must list at least one contract under `contracts:` — the contract number is one of the nine FAR 52.204-25(d)(2)(i) reporting elements.');
  }
  const contracts: Section889Contact[] = rows.map((row: any, i: number) => {
    const contractNumber = asString(row?.contract_number);
    if (!contractNumber) {
      throw new Section889ContactsError(`contracts[${i}].contract_number`, `contracts[${i}] is missing contract_number (a required FAR 52.204-25(d)(2)(i) reporting element).`);
    }
    if (!FAR_CONTRACT_RE.test(contractNumber)) {
      throw new Section889ContactsError(`contracts[${i}].contract_number`, `contracts[${i}].contract_number "${contractNumber}" does not look like a federal contract number.`);
    }
    const endpointRaw = asString(row?.endpoint_type);
    const endpointType: Section889EndpointType = endpointRaw === 'dod-dibnet' ? 'dod-dibnet' : 'civilian-co-email';
    const contractingOfficerEmail = asString(row?.contracting_officer_email);
    if (contractingOfficerEmail && !EMAIL_RE.test(contractingOfficerEmail)) {
      throw new Section889ContactsError(`contracts[${i}].contracting_officer_email`, `contracts[${i}].contracting_officer_email "${contractingOfficerEmail}" is not a valid email address.`);
    }
    if (endpointType === 'civilian-co-email' && !contractingOfficerEmail) {
      throw new Section889ContactsError(`contracts[${i}].contracting_officer_email`, `contracts[${i}] (${contractNumber}) is a civilian contract but has no contracting_officer_email — the FAR 52.204-25(d) report cannot be addressed.`);
    }
    return {
      contractNumber,
      agency: asString(row?.agency),
      endpointType,
      contractingOfficerEmail,
      primeContractorUei: asString(row?.prime_contractor_uei),
      cageCode: asString(row?.cage_code),
    };
  });
  return {
    schemaVersion: asString(obj.schema_version) ?? '1.0.0',
    contracts,
  };
}

/** Load + normalize the contacts from a YAML path. A missing file throws. */
export function loadSection889Contacts(path: string): Section889Contacts {
  if (!existsSync(path)) {
    throw new Section889ContactsError('(file)', `section889-contacts.yaml not found at ${path}. The FAR 52.204-25(d) 1-business-day report cannot be addressed without the Contracting Officer mapping. Copy section889-contacts.example.yaml and fill it in.`);
  }
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new Section889ContactsError('(file)', `Cannot read section889-contacts.yaml at ${path}: ${(e as Error)?.message ?? String(e)}`);
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch (e) {
    throw new Section889ContactsError('(yaml)', `section889-contacts.yaml at ${path} is not valid YAML: ${(e as Error)?.message ?? String(e)}`);
  }
  return normalizeSection889Contacts(parsed);
}
