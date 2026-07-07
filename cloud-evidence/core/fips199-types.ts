/**
 * NIST SP 800-60 Vol. 2 Rev. 1 — information-type catalogue (SaaS-relevant subset) — LOOP-C.C5.
 *
 * FIPS 199 security categorization (RA-2) works by identifying the information
 * types the system processes, assigning each a confidentiality / integrity /
 * availability impact level, and taking the system-level high-water-mark. The
 * information-type taxonomy is published by NIST in SP 800-60 Vol. 2 Rev. 1
 * (Appendix C — Management and Support Information; Appendix D — Mission-Based
 * Information). This module exports the SaaS-relevant subset of that taxonomy —
 * the Management and Support information types (Appendix C) a cloud service
 * provider's own system most plausibly processes.
 *
 * Authoritative source (verbatim codes + names — REO Rule 3 allowed exception:
 * NIST-published identifiers are fixed data, like NIST control IDs):
 *   - NIST SP 800-60 Vol. 2 Rev. 1 (August 2008), "Appendices to Guide for
 *     Mapping Types of Information and Information Systems to Security
 *     Categories" — Appendix C (Management and Support Information and
 *     Information System Impact Levels) —
 *     https://csrc.nist.gov/pubs/sp/800/60/v2/r1/final
 *     https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-60v2r1.pdf
 *
 * SOURCE_VERSION documents the pinned catalogue revision so a later re-extract
 * (SP 800-60 Rev. 2 is in Initial Working Draft as of January 2024; not final)
 * is traceable — when Rev. 2 finalizes, re-extract the catalogue and bump the
 * constant (see LOOP-C-RISKS C-C5-1).
 *
 * NOTE on impact levels: this catalogue deliberately carries ONLY the published
 * code + name (+ the FEA business area they sit under). It does NOT assert
 * per-type provisional confidentiality/integrity/availability recommendations —
 * the operator supplies the actual C/I/A for each information type they select
 * (per RA-2, the categorization is the system owner's determination), and may
 * consult SP 800-60 Vol. 2 Rev. 1's recommended provisional impact levels
 * directly. Emitting a provisional triad we are not certain of verbatim would
 * violate REO Rule 1.3 (no fabricated data in a production path).
 */

/** Pinned catalogue revision — bump on a Rev. 2 re-extract (LOOP-C-RISKS C-C5-1). */
export const SOURCE_VERSION = 'SP 800-60 Vol. 2 Rev. 1';

/** Source URL cited in the emitted worksheet provenance footer. */
export const SOURCE_URL = 'https://csrc.nist.gov/pubs/sp/800/60/v2/r1/final';

/** One catalogue entry: a NIST-published information type code + name. */
export interface InformationTypeCatalogEntry {
  /** SP 800-60 V2 R1 code, e.g. "C.3.5.1". */
  code: string;
  /** Verbatim SP 800-60 V2 R1 information-type name. */
  name: string;
  /** Appendix the type is published in ("C" = Management and Support). */
  appendix: 'C';
  /** FEA business area the type sits under (for grouping in §3). */
  category:
    | 'Services Delivery Support'
    | 'Government Resource Management'
    | 'Information and Technology Management';
}

/**
 * The SaaS-relevant subset of the SP 800-60 Vol. 2 Rev. 1 Appendix C taxonomy.
 * A cloud service provider's authorization-boundary system predominantly
 * processes Management and Support information (about the service itself);
 * mission-based (Appendix D) types are agency-specific and left to the
 * operator to add via config when a specific mission information type applies.
 *
 * Codes + names are verbatim from SP 800-60 V2 R1 Appendix C. The
 * Information and Technology Management family (C.3.5.x) is the most directly
 * applicable to a CSP and is enumerated in full.
 */
export const INFORMATION_TYPE_CATALOG: readonly InformationTypeCatalogEntry[] = [
  // ── C.2 Services Delivery Support ──
  { code: 'C.2.1', name: 'Controls and Oversight', appendix: 'C', category: 'Services Delivery Support' },
  { code: 'C.2.2', name: 'Regulatory Development', appendix: 'C', category: 'Services Delivery Support' },
  { code: 'C.2.3', name: 'Planning and Budgeting', appendix: 'C', category: 'Services Delivery Support' },
  { code: 'C.2.4', name: 'Internal Risk Management and Mitigation', appendix: 'C', category: 'Services Delivery Support' },
  { code: 'C.2.5', name: 'Revenue Collection', appendix: 'C', category: 'Services Delivery Support' },
  { code: 'C.2.6', name: 'Public Affairs', appendix: 'C', category: 'Services Delivery Support' },
  { code: 'C.2.7', name: 'Legislative Relations', appendix: 'C', category: 'Services Delivery Support' },
  { code: 'C.2.8', name: 'General Government', appendix: 'C', category: 'Services Delivery Support' },

  // ── C.3 Government Resource Management ──
  { code: 'C.3.1', name: 'Administrative Management', appendix: 'C', category: 'Government Resource Management' },
  { code: 'C.3.2', name: 'Financial Management', appendix: 'C', category: 'Government Resource Management' },
  { code: 'C.3.3', name: 'Human Resources Management', appendix: 'C', category: 'Government Resource Management' },
  { code: 'C.3.4', name: 'Supply Chain Management', appendix: 'C', category: 'Government Resource Management' },

  // ── C.3.5 Information and Technology Management (most CSP-relevant) ──
  { code: 'C.3.5.1', name: 'System Development', appendix: 'C', category: 'Information and Technology Management' },
  { code: 'C.3.5.2', name: 'Lifecycle/Change Management', appendix: 'C', category: 'Information and Technology Management' },
  { code: 'C.3.5.3', name: 'System Maintenance', appendix: 'C', category: 'Information and Technology Management' },
  { code: 'C.3.5.4', name: 'IT Infrastructure Maintenance', appendix: 'C', category: 'Information and Technology Management' },
  { code: 'C.3.5.5', name: 'Information Security', appendix: 'C', category: 'Information and Technology Management' },
  { code: 'C.3.5.6', name: 'Record Retention', appendix: 'C', category: 'Information and Technology Management' },
  { code: 'C.3.5.7', name: 'Information Management', appendix: 'C', category: 'Information and Technology Management' },
  { code: 'C.3.5.8', name: 'System and Network Monitoring', appendix: 'C', category: 'Information and Technology Management' },
  { code: 'C.3.5.9', name: 'Information Sharing', appendix: 'C', category: 'Information and Technology Management' },
] as const;

/** Fast O(1) code → entry lookup (codes are unique). */
const BY_CODE: ReadonlyMap<string, InformationTypeCatalogEntry> = new Map(
  INFORMATION_TYPE_CATALOG.map((e) => [e.code, e]),
);

/** Return the catalogue entry for a code, or undefined if not in the subset. */
export function findInformationType(code: string): InformationTypeCatalogEntry | undefined {
  return BY_CODE.get(code.trim());
}

/**
 * Verbatim SP 800-60 Vol. 2 Rev. 1 selection guidance quoted in the §3
 * fallback row when the operator supplies no information types. Directs the
 * operator to the published catalogue rather than fabricating a default type.
 */
export const SELECTION_GUIDANCE =
  'Select the information types this system processes, stores, or transmits from the ' +
  'NIST SP 800-60 Vol. 2 Rev. 1 catalogue (Appendix C — Management and Support Information; ' +
  'Appendix D — Mission-Based Information). Assign each a confidentiality, integrity, and ' +
  'availability impact level (LOW / MODERATE / HIGH; NOT APPLICABLE is permitted only for ' +
  'confidentiality). The Management and Support subset most relevant to a cloud service ' +
  'provider is exported by core/fips199-types.ts (' + SOURCE_VERSION + ').';
