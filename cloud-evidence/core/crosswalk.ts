/**
 * Multi-framework crosswalk.
 *
 * The same controls a FedRAMP 20x KSI satisfies are usually ALSO required by
 * SOC 2, ISO 27001, and HIPAA — but each framework names them differently.
 * If we're already collecting the evidence, the marginal cost of also
 * emitting it under SOC 2 / ISO / HIPAA labels is near-zero. The marginal
 * VALUE is high: a single run of cloud-evidence can feed every framework
 * the CSP is on the hook for.
 *
 * Mapping authority:
 *   - NIST OLIR (Online Informative References) Catalog is the
 *     authoritative cross-reference. We embed a curated subset (the controls
 *     most relevant to cloud KSIs) here. For a full audit, an organization
 *     should cross-check against:
 *       NIST SP 800-53 ↔ ISO/IEC 27001:2022 Annex A:
 *         https://csrc.nist.gov/files/pubs/sp/800/53/r5/upd1/final/docs/sp800-53r5-to-iso-27001-mapping.docx
 *       NIST SP 800-53 ↔ AICPA TSC (SOC 2):
 *         https://www.aicpa.org/resources/download/trust-services-criteria-mapping
 *       NIST SP 800-53 ↔ HIPAA Security Rule:
 *         https://csrc.nist.gov/projects/olir/informative-reference-catalog
 *   - These public mappings change occasionally; this file is intentionally
 *     small and easy to audit. To extend, add rows to NIST_TO_FRAMEWORKS.
 *
 * Scope:
 *   - We map at the NIST control family + control level (e.g. "IA-2(1)").
 *     Sub-statements aren't broken out.
 *   - We do NOT replace a 3PAO's judgment — a control mapping is a starting
 *     point, not a guarantee that the implementation satisfies the framework.
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type { EvidenceFile } from './envelope.ts';
import { log } from './log.ts';

export type Framework = 'NIST_800_53' | 'SOC2' | 'ISO_27001' | 'HIPAA';

export interface FrameworkRef {
  framework: Framework;
  control_id: string;
  title?: string;
}

/**
 * Curated NIST 800-53 → other frameworks crosswalk. Keyed by NIST control
 * (e.g. "IA-2"). Covers the controls our KSI catalog actually maps to.
 *
 * SOC2 references use the AICPA Trust Services Criteria notation:
 *   CC = Common Criteria (security)
 *   A  = Availability
 *   PI = Processing Integrity
 *   C  = Confidentiality
 *   P  = Privacy
 *
 * ISO 27001 references are 2022 revision Annex A control numbers.
 */
const NIST_TO_FRAMEWORKS: Record<string, Array<{ framework: Framework; control_id: string; title?: string }>> = {
  // ---- Access Control ----
  'AC-2': [
    { framework: 'SOC2', control_id: 'CC6.2', title: 'Authorize, modify, or remove access' },
    { framework: 'ISO_27001', control_id: 'A.5.16', title: 'Identity management' },
    { framework: 'HIPAA', control_id: '§164.308(a)(4)', title: 'Information access management' },
  ],
  'AC-3': [
    { framework: 'SOC2', control_id: 'CC6.1', title: 'Logical and physical access controls' },
    { framework: 'ISO_27001', control_id: 'A.5.15', title: 'Access control' },
    { framework: 'HIPAA', control_id: '§164.312(a)(1)', title: 'Access control' },
  ],
  'AC-4': [
    { framework: 'SOC2', control_id: 'CC6.6', title: 'Boundary protection' },
    { framework: 'ISO_27001', control_id: 'A.8.20', title: 'Networks security' },
  ],
  'AC-5': [
    { framework: 'SOC2', control_id: 'CC6.3', title: 'Logical access — segregation of duties' },
    { framework: 'ISO_27001', control_id: 'A.5.3', title: 'Segregation of duties' },
  ],
  'AC-6': [
    { framework: 'SOC2', control_id: 'CC6.3', title: 'Least privilege' },
    { framework: 'ISO_27001', control_id: 'A.8.2', title: 'Privileged access rights' },
    { framework: 'HIPAA', control_id: '§164.312(a)(2)(i)', title: 'Unique user identification' },
  ],
  'AC-17': [
    { framework: 'SOC2', control_id: 'CC6.6', title: 'Remote access' },
    { framework: 'ISO_27001', control_id: 'A.6.7', title: 'Remote working' },
    { framework: 'HIPAA', control_id: '§164.312(e)(1)', title: 'Transmission security' },
  ],
  // ---- Audit & Accountability ----
  'AU-2': [
    { framework: 'SOC2', control_id: 'CC7.2', title: 'System monitoring' },
    { framework: 'ISO_27001', control_id: 'A.8.15', title: 'Logging' },
    { framework: 'HIPAA', control_id: '§164.312(b)', title: 'Audit controls' },
  ],
  'AU-3': [
    { framework: 'SOC2', control_id: 'CC7.2' },
    { framework: 'ISO_27001', control_id: 'A.8.15' },
    { framework: 'HIPAA', control_id: '§164.312(b)' },
  ],
  'AU-6': [
    { framework: 'SOC2', control_id: 'CC7.3', title: 'Anomaly detection and analysis' },
    { framework: 'ISO_27001', control_id: 'A.8.16', title: 'Monitoring activities' },
  ],
  'AU-9': [
    { framework: 'SOC2', control_id: 'CC7.2' },
    { framework: 'ISO_27001', control_id: 'A.8.15' },
    { framework: 'HIPAA', control_id: '§164.312(c)(1)', title: 'Integrity controls' },
  ],
  'AU-11': [
    { framework: 'SOC2', control_id: 'CC7.2' },
    { framework: 'ISO_27001', control_id: 'A.8.15' },
  ],
  'AU-12': [
    { framework: 'SOC2', control_id: 'CC7.2' },
    { framework: 'ISO_27001', control_id: 'A.8.15' },
  ],
  // ---- Configuration Management ----
  'CM-2': [
    { framework: 'SOC2', control_id: 'CC8.1', title: 'Change management' },
    { framework: 'ISO_27001', control_id: 'A.8.32', title: 'Change management' },
  ],
  'CM-6': [
    { framework: 'SOC2', control_id: 'CC7.1', title: 'Detection of configuration changes' },
    { framework: 'ISO_27001', control_id: 'A.8.9', title: 'Configuration management' },
  ],
  'CM-7': [
    { framework: 'SOC2', control_id: 'CC6.6', title: 'Least functionality' },
    { framework: 'ISO_27001', control_id: 'A.8.19', title: 'Installation of software on operational systems' },
  ],
  'CM-8': [
    { framework: 'SOC2', control_id: 'CC6.1', title: 'System inventory' },
    { framework: 'ISO_27001', control_id: 'A.5.9', title: 'Inventory of information and other associated assets' },
    { framework: 'HIPAA', control_id: '§164.310(d)(1)', title: 'Device and media controls' },
  ],
  // ---- Contingency Planning ----
  'CP-9': [
    { framework: 'SOC2', control_id: 'A1.2', title: 'Backups' },
    { framework: 'ISO_27001', control_id: 'A.8.13', title: 'Information backup' },
    { framework: 'HIPAA', control_id: '§164.308(a)(7)(ii)(A)', title: 'Data backup plan' },
  ],
  'CP-10': [
    { framework: 'SOC2', control_id: 'A1.2', title: 'Recovery operations' },
    { framework: 'ISO_27001', control_id: 'A.5.30', title: 'ICT readiness for business continuity' },
    { framework: 'HIPAA', control_id: '§164.308(a)(7)(ii)(C)', title: 'Emergency mode operation plan' },
  ],
  // ---- Identification & Authentication ----
  'IA-2': [
    { framework: 'SOC2', control_id: 'CC6.1', title: 'Logical access — identification & authentication' },
    { framework: 'ISO_27001', control_id: 'A.5.17', title: 'Authentication information' },
    { framework: 'HIPAA', control_id: '§164.312(d)', title: 'Person or entity authentication' },
  ],
  'IA-2(1)': [
    { framework: 'SOC2', control_id: 'CC6.1' },
    { framework: 'ISO_27001', control_id: 'A.5.17' },
    { framework: 'HIPAA', control_id: '§164.312(d)' },
  ],
  'IA-2(2)': [
    { framework: 'SOC2', control_id: 'CC6.1', title: 'MFA for non-privileged users' },
    { framework: 'ISO_27001', control_id: 'A.5.17' },
  ],
  'IA-2(8)': [
    { framework: 'SOC2', control_id: 'CC6.1', title: 'MFA replay-resistance' },
    { framework: 'ISO_27001', control_id: 'A.5.17' },
  ],
  'IA-5': [
    { framework: 'SOC2', control_id: 'CC6.1', title: 'Authenticator management' },
    { framework: 'ISO_27001', control_id: 'A.5.17' },
    { framework: 'HIPAA', control_id: '§164.308(a)(5)(ii)(D)', title: 'Password management' },
  ],
  // ---- Incident Response ----
  'IR-4': [
    { framework: 'SOC2', control_id: 'CC7.4', title: 'Incident response' },
    { framework: 'ISO_27001', control_id: 'A.5.24', title: 'Information security incident management planning' },
    { framework: 'HIPAA', control_id: '§164.308(a)(6)', title: 'Security incident procedures' },
  ],
  'IR-5': [
    { framework: 'SOC2', control_id: 'CC7.3' },
    { framework: 'ISO_27001', control_id: 'A.5.25', title: 'Assessment of information security events' },
  ],
  // ---- Risk Assessment ----
  'RA-3': [
    { framework: 'SOC2', control_id: 'CC3.2', title: 'Risk identification' },
    { framework: 'ISO_27001', control_id: 'A.5.7', title: 'Threat intelligence' },
  ],
  'RA-5': [
    { framework: 'SOC2', control_id: 'CC7.1', title: 'Vulnerability scanning' },
    { framework: 'ISO_27001', control_id: 'A.8.8', title: 'Management of technical vulnerabilities' },
  ],
  // ---- System & Communications Protection ----
  'SC-7': [
    { framework: 'SOC2', control_id: 'CC6.6', title: 'Boundary protection' },
    { framework: 'ISO_27001', control_id: 'A.8.20' },
    { framework: 'HIPAA', control_id: '§164.312(e)(1)' },
  ],
  'SC-8': [
    { framework: 'SOC2', control_id: 'CC6.7', title: 'Transmission of data' },
    { framework: 'ISO_27001', control_id: 'A.8.24', title: 'Use of cryptography' },
    { framework: 'HIPAA', control_id: '§164.312(e)(2)(ii)', title: 'Encryption' },
  ],
  'SC-12': [
    { framework: 'SOC2', control_id: 'CC6.1' },
    { framework: 'ISO_27001', control_id: 'A.8.24' },
  ],
  'SC-13': [
    { framework: 'SOC2', control_id: 'CC6.7' },
    { framework: 'ISO_27001', control_id: 'A.8.24' },
    { framework: 'HIPAA', control_id: '§164.312(a)(2)(iv)', title: 'Encryption and decryption' },
  ],
  'SC-28': [
    { framework: 'SOC2', control_id: 'CC6.7', title: 'Protection at rest' },
    { framework: 'ISO_27001', control_id: 'A.8.24' },
    { framework: 'HIPAA', control_id: '§164.312(a)(2)(iv)' },
  ],
  // ---- System & Information Integrity ----
  'SI-2': [
    { framework: 'SOC2', control_id: 'CC7.1', title: 'Flaw remediation (patching)' },
    { framework: 'ISO_27001', control_id: 'A.8.8' },
  ],
  'SI-3': [
    { framework: 'SOC2', control_id: 'CC6.8', title: 'Malicious code protection' },
    { framework: 'ISO_27001', control_id: 'A.8.7', title: 'Protection against malware' },
  ],
  'SI-4': [
    { framework: 'SOC2', control_id: 'CC7.2' },
    { framework: 'ISO_27001', control_id: 'A.8.16' },
  ],
  'SI-7': [
    { framework: 'SOC2', control_id: 'CC7.2', title: 'Integrity verification' },
    { framework: 'ISO_27001', control_id: 'A.8.13' },
  ],
};

export interface MapResult {
  /** The control ID we looked up. */
  nist_control: string;
  /** Cross-framework refs we found. */
  refs: FrameworkRef[];
  /** True if no mapping exists for this control. */
  unmapped: boolean;
}

/**
 * Look up a NIST control's cross-framework references. Falls back to the
 * parent control (without enhancement number) if the specific one isn't
 * mapped: e.g. lookup of "AC-2(1)" returns whatever "AC-2" maps to.
 */
export function mapNistToFrameworks(controlId: string): MapResult {
  const direct = NIST_TO_FRAMEWORKS[controlId];
  if (direct) return { nist_control: controlId, refs: [...direct], unmapped: false };

  // Strip enhancement: "AC-2(1)" → "AC-2"
  const stripped = controlId.replace(/\(\d+\)$/, '');
  if (stripped !== controlId) {
    const parent = NIST_TO_FRAMEWORKS[stripped];
    if (parent) return { nist_control: controlId, refs: [...parent], unmapped: false };
  }
  return { nist_control: controlId, refs: [], unmapped: true };
}

export interface CrosswalkSummary {
  framework: Framework;
  controls_referenced: Array<{
    control_id: string;
    title?: string;
    ksis: string[];           // KSIs that touch this control
    failing_ksis: string[];   // ksis where at least one finding failed
    failing_findings_total: number;
  }>;
}

export interface CrosswalkReport {
  generated_at: string;
  framework_summaries: CrosswalkSummary[];
  /** NIST controls referenced in evidence but not mapped to any other framework. */
  unmapped_nist_controls: string[];
  /** KSIs with no NIST control mapping at all (edge case). */
  ksis_without_nist: string[];
  total_ksis_analyzed: number;
}

/**
 * Build a cross-framework report from the EvidenceFiles in `outDir`.
 *
 * Emits `crosswalk-report.json` next to the evidence by default.
 */
export function buildCrosswalkReport(outDir: string, outPath?: string): CrosswalkReport {
  const files = readdirSync(outDir).filter((f) => f.startsWith('KSI-') && f.endsWith('.json') && !f.includes('CSX-SUM'));
  const perFramework: Map<Framework, Map<string, CrosswalkSummary['controls_referenced'][number]>> = new Map();
  const unmappedControls = new Set<string>();
  const ksisWithoutNist: string[] = [];
  let analyzed = 0;

  for (const file of files) {
    let ef: EvidenceFile;
    try {
      ef = JSON.parse(readFileSync(resolve(outDir, file), 'utf8'));
    } catch {
      continue;
    }
    analyzed++;

    // Collect all NIST controls referenced by this KSI (top-level + per-finding)
    const nistControls = new Set<string>(ef.nist_controls ?? []);
    let failingFindings = 0;
    let anyFailing = false;
    for (const p of ef.providers) {
      for (const f of p.findings) {
        for (const c of f.nist_controls ?? []) nistControls.add(c);
        if (!f.passed) {
          failingFindings++;
          anyFailing = true;
        }
      }
    }
    if (nistControls.size === 0) {
      ksisWithoutNist.push(ef.ksi_id);
      continue;
    }

    for (const c of nistControls) {
      const m = mapNistToFrameworks(c);
      if (m.unmapped) unmappedControls.add(c);
      for (const ref of m.refs) {
        if (!perFramework.has(ref.framework)) perFramework.set(ref.framework, new Map());
        const fwMap = perFramework.get(ref.framework)!;
        const key = ref.control_id;
        if (!fwMap.has(key)) fwMap.set(key, { control_id: key, title: ref.title, ksis: [], failing_ksis: [], failing_findings_total: 0 });
        const row = fwMap.get(key)!;
        if (!row.ksis.includes(ef.ksi_id)) row.ksis.push(ef.ksi_id);
        if (anyFailing && !row.failing_ksis.includes(ef.ksi_id)) row.failing_ksis.push(ef.ksi_id);
        row.failing_findings_total += failingFindings;
      }
    }
  }

  const frameworkSummaries: CrosswalkSummary[] = Array.from(perFramework.entries()).map(([framework, m]) => ({
    framework,
    controls_referenced: Array.from(m.values()).sort((a, b) => a.control_id.localeCompare(b.control_id)),
  })).sort((a, b) => a.framework.localeCompare(b.framework));

  const report: CrosswalkReport = {
    generated_at: new Date().toISOString(),
    framework_summaries: frameworkSummaries,
    unmapped_nist_controls: Array.from(unmappedControls).sort(),
    ksis_without_nist: ksisWithoutNist.sort(),
    total_ksis_analyzed: analyzed,
  };

  const path = outPath ?? resolve(outDir, 'crosswalk-report.json');
  writeFileSync(path, JSON.stringify(report, null, 2));
  log.info({ event: 'crosswalk.emitted', path, frameworks: frameworkSummaries.length, unmapped: unmappedControls.size });

  return report;
}

/** Exposed for tests. */
export const _internal = { NIST_TO_FRAMEWORKS };
