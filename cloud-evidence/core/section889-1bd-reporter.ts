/**
 * FAR 52.204-25(d) 1-business-day prohibited-vendor discovery reporter
 * (LOOP-W.W3) — disk + signing + docx + ledger + coverage + notification.
 *
 * Ingests the W.W2 screen-result envelope (out/prohibited-vendors-screen-result.json),
 * verifies its detached Ed25519 signature, filters the reportable matches
 * (non-suppressed, high-confidence, Section 889 / Kaspersky / operator-addition
 * source), computes the federal-business-day deadline for each, composes one
 * signed canonical-JSON report + a rendered `.docx` per (match × affected
 * contract), records each emission in an append-only ledger (the idempotency
 * substrate — re-running the same screen never double-reports), augments
 * inventory-coverage.json, and raises an emit-time notification.
 *
 * The reporter NEVER transmits to a federal endpoint — REO Rule 4 forbids the
 * system from acting on the operator's behalf on a regulatory submission. It
 * produces the artifact pair (signed JSON + `.docx`); the operator transmits.
 *
 * REO compliance: the W.W2 envelope's signature is verified before any output
 * is written (a forged screen could mask or fabricate a reportable hit); the
 * nine (d)(2)(i) elements are read from the W.W2 match record (operator
 * `REQUIRES-OPERATOR-INPUT` markers are preserved, never auto-filled); every
 * emitted JSON carries a top-level camelCase provenance block (G3); no human
 * attestation is auto-signed (the operator's name/title flow from config and
 * the wet-signature region is left for the operator).
 */
import {
  readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync,
} from 'node:fs';
import { resolve, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalize, signDetached, verifyDetached } from './sign.ts';
import { log } from './log.ts';
import {
  SCREEN_RESULT_FILENAME,
  type ProhibitedVendorScreenResult,
  type ProhibitedVendorMatch,
} from './prohibited-vendors-screen.ts';
import {
  isReportableMatch, composeReportEnvelope, canonicalReportBytes, pendingOperatorFields,
  reportIdFor,
  SECTION889_REPORTS_DIRNAME, SECTION889_REPORTS_LEDGER,
  type Section8891bdReport, type Section889ReportKind, type Section889DiscoveryKind,
  type Section889SigningOfficer, type FarD2iiContent,
} from './section889-report-json.ts';
import { renderSection889ReportDocx } from './section889-report-docx.ts';
import {
  loadSection889Contacts, type Section889Contact, type Section889Contacts,
} from './section889-contacts.ts';
import { loadSection889Closures, closureDateSet } from './section889-closures.ts';
import {
  deadlineFor, followUpDeadlineFor, businessHoursRemaining, DEFAULT_BUSINESS_TZ,
  type FederalClockOptions,
} from './section889-clock.ts';

export const REQUIRES_OPERATOR_INPUT = 'REQUIRES-OPERATOR-INPUT';

/** Thrown when the W.W2 screen envelope's signature does not verify. */
export class EnvelopeSignatureInvalidError extends Error {
  readonly path: string;
  constructor(path: string) {
    super(`section889-1bd-reporter: W.W2 screen-result signature did not verify at ${path}; refusing to compose a report from an unverifiable screen (a forged screen could fabricate or mask a reportable identification).`);
    this.name = 'EnvelopeSignatureInvalidError';
    this.path = path;
  }
}

/** Thrown (strict mode only) when the corporate signing officer is unconfigured. */
export class Section889OperatorConfigMissingError extends Error {
  readonly fields: string[];
  constructor(fields: string[]) {
    super(`section889-1bd-reporter: cannot emit a FAR 52.204-25(d) report — required operator config missing: ${fields.join(', ')}. Set section_889.signing in config.yaml (corporate_signing_officer_name / _title).`);
    this.name = 'Section889OperatorConfigMissingError';
    this.fields = fields;
  }
}

export interface Section889Notification {
  kind: 'emitted' | 'deadline-warning';
  report_id: string;
  vendor: string;
  contract_number: string;
  deadline_at: string;
  business_hours_remaining: number;
  report_path_json: string;
  report_path_docx: string;
}

export type Section889Notifier = (n: Section889Notification) => void;

export interface Section8891bdReportOptions {
  outDir: string;
  runId: string;
  cspName: string;
  cspUei?: string;
  cspCageCode?: string;

  /** W.W2 envelope path. Defaults to <outDir>/prohibited-vendors-screen-result.json. */
  screenEnvelopePath?: string;
  /** Verify the W.W2 envelope signature before consuming it. Default true. */
  verifyScreenSignature?: boolean;

  /** section889-contacts.yaml path (required to address civilian reports). */
  contactsPath?: string;
  /** section889-agency-closures.yaml path (optional). */
  closuresPath?: string;

  signingOfficerName?: string;
  signingOfficerTitle?: string;

  federalBusinessHoursTz?: string;
  businessHours?: { openHour?: number; closeHour?: number; businessHoursPerDay?: number };

  discoveryKind?: Section889DiscoveryKind;
  waiverId?: string | null;

  /** Deterministic clock (tests). Defaults to now. */
  emittedAt?: string;

  /** When true, throw Section889OperatorConfigMissingError if the officer is unset. */
  strict?: boolean;

  /** Notification seam (tests inject a stub). Defaults to env-gated Slack/PagerDuty. */
  notify?: Section889Notifier;
}

export interface Section889EmittedReport {
  report_id: string;
  report_kind: Section889ReportKind;
  contract_number: string;
  vendor: string;
  json_path: string;
  sig_path: string;
  docx_path: string;
  deadline_at: string;
  business_hours_remaining_at_emit: number;
  pending_operator_fields: string[];
}

export interface Section8891bdReportResult {
  reports: Section889EmittedReport[];
  reports_emitted: number;
  reports_already_present: number;
  reportable_matches: number;
  deadline_breached_at_emit: number;
  follow_ups_scheduled: number;
  ledger_path: string;
  requires_operator_input: string[];
}

interface LedgerKey { run_id: string; match_id: string; contract_number: string; report_kind: Section889ReportKind; }

function ledgerKeyStr(k: LedgerKey): string {
  return `${k.run_id}|${k.match_id}|${k.contract_number}|${k.report_kind}`;
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function relForProvenance(outDir: string, path: string): string {
  try { if (resolve(path).startsWith(resolve(outDir))) return basename(path); } catch { /* fall through */ }
  return path;
}

/** Re-derive the W.W2 envelope's canonical signature-blanked bytes for verification. */
function w2CanonicalBlanked(env: ProhibitedVendorScreenResult): string {
  const blanked = {
    ...env,
    provenance: { ...env.provenance, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
  return canonicalize(JSON.parse(JSON.stringify(blanked)));
}

/** Read the already-reported idempotency keys from the ledger. */
function readLedgerKeys(ledgerPath: string): Set<string> {
  const keys = new Set<string>();
  if (!existsSync(ledgerPath)) return keys;
  try {
    for (const line of readFileSync(ledgerPath, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t) continue;
      const rec = JSON.parse(t);
      if (rec?.run_id && rec?.match_id && rec?.contract_number && rec?.report_kind) {
        keys.add(ledgerKeyStr(rec));
      }
    }
  } catch (e) {
    log.warn({ event: 'w.w3.ledger_read_failed', err: String((e as Error)?.message ?? e) });
  }
  return keys;
}

/** Default notifier: env-gated, best-effort Slack/PagerDuty (fire-and-forget). */
function defaultNotifier(n: Section889Notification): void {
  const slack = process.env.SLACK_WEBHOOK_URL;
  const pd = process.env.PAGERDUTY_INTEGRATION_KEY;
  if (!slack && !pd) return;
  const urgent = n.kind === 'deadline-warning';
  const summary = n.kind === 'emitted'
    ? `FAR 52.204-25(d) 1BD report emitted for ${n.vendor} on contract ${n.contract_number} — deadline ${n.deadline_at} (${n.business_hours_remaining}h business remaining)`
    : `FAR 52.204-25(d) 1BD deadline approaching for ${n.vendor} on ${n.contract_number} — ${n.deadline_at}`;
  if (slack) {
    void fetch(slack, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: `${urgent ? ':rotating_light: ' : ''}${summary}` }),
    }).catch(() => { /* best effort */ });
  }
  if (pd && urgent) {
    void fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        routing_key: pd, event_action: 'trigger',
        dedup_key: `section889-1bd-${n.report_id}`,
        payload: { summary, severity: 'error', source: 'cloud-evidence/section889-1bd-reporter' },
      }),
    }).catch(() => { /* best effort */ });
  }
}

/**
 * Resolve the contracts a match must be reported against. When the match's FAR
 * data carries explicit contract numbers, report only against those (matched to
 * the operator's contacts where known). Otherwise report against every contract
 * in section889-contacts.yaml — the FAR-default conservative posture (the clause
 * does not narrow scope; the contractor errs toward over-reporting).
 */
function affectedContracts(m: ProhibitedVendorMatch, contacts: Section889Contacts): Section889Contact[] {
  const explicit = (m.far_52_204_25_d_data_elements.contract_numbers ?? []).filter(Boolean);
  if (explicit.length === 0) return contacts.contracts;
  const byNumber = new Map(contacts.contracts.map((c) => [c.contractNumber, c]));
  return explicit.map((num) =>
    byNumber.get(num) ?? {
      contractNumber: num,
      agency: null,
      endpointType: 'civilian-co-email' as const,
      contractingOfficerEmail: null,
      primeContractorUei: null,
      cageCode: null,
    });
}

/**
 * End-to-end W.W3 pass: ingest + verify the W.W2 envelope, emit one signed
 * report (JSON + `.docx`) per reportable (match × contract), dedupe via the
 * ledger, augment coverage, and notify. Returns a summary; throws only on a
 * signature-verification failure (or, in strict mode, missing operator config).
 */
export function emitSection8891bdReports(opts: Section8891bdReportOptions): Section8891bdReportResult {
  const emittedAt = opts.emittedAt ?? new Date().toISOString();
  const tz = opts.federalBusinessHoursTz ?? DEFAULT_BUSINESS_TZ;
  const screenPath = opts.screenEnvelopePath ?? resolve(opts.outDir, SCREEN_RESULT_FILENAME);
  const notify = opts.notify ?? defaultNotifier;

  if (!existsSync(screenPath)) {
    throw new Error(`section889-1bd-reporter: W.W2 screen result not found at ${screenPath}. Run --prohibited-vendor-screen (W.W2) first.`);
  }
  const screen = JSON.parse(readFileSync(screenPath, 'utf8')) as ProhibitedVendorScreenResult;

  // ── Verify the W.W2 envelope signature (REO: never report from a forged screen) ──
  if (opts.verifyScreenSignature !== false) {
    const canonical = w2CanonicalBlanked(screen);
    const ok = !!screen.provenance?.signatureEd25519 && !!screen.provenance?.publicKeyPem
      && verifyDetached(Buffer.from(canonical, 'utf8'), {
        publicKeyPem: screen.provenance.publicKeyPem,
        signatureBase64: screen.provenance.signatureEd25519,
      });
    if (!ok) throw new EnvelopeSignatureInvalidError(screenPath);
  }

  const screenSha = sha256Hex(readFileSync(screenPath));
  const reportable = (screen.matches ?? []).filter(isReportableMatch);

  const officerName = opts.signingOfficerName?.trim() || REQUIRES_OPERATOR_INPUT;
  const officerTitle = opts.signingOfficerTitle?.trim() || REQUIRES_OPERATOR_INPUT;
  const requiresOperatorInput: string[] = [];
  if (officerName === REQUIRES_OPERATOR_INPUT) requiresOperatorInput.push('section_889.signing.corporate_signing_officer_name');
  if (officerTitle === REQUIRES_OPERATOR_INPUT) requiresOperatorInput.push('section_889.signing.corporate_signing_officer_title');
  if (opts.strict && reportable.length > 0 && requiresOperatorInput.length > 0) {
    throw new Section889OperatorConfigMissingError(requiresOperatorInput);
  }

  const ledgerPath = resolve(opts.outDir, SECTION889_REPORTS_LEDGER);
  const result: Section8891bdReportResult = {
    reports: [], reports_emitted: 0, reports_already_present: 0,
    reportable_matches: reportable.length, deadline_breached_at_emit: 0,
    follow_ups_scheduled: 0, ledger_path: ledgerPath, requires_operator_input: requiresOperatorInput,
  };
  if (reportable.length === 0) {
    log.info({ event: 'w.w3.no_reportable_matches', run_id: opts.runId, screen_path: screenPath });
    return result;
  }

  // ── Load operator routing + closures ──
  const contactsPath = opts.contactsPath ?? resolve(process.cwd(), 'section889-contacts.yaml');
  const contacts = loadSection889Contacts(contactsPath);
  const closures = loadSection889Closures(opts.closuresPath ?? resolve(process.cwd(), 'section889-agency-closures.yaml'));
  const clockOpts: FederalClockOptions = {
    tz,
    openHour: opts.businessHours?.openHour,
    closeHour: opts.businessHours?.closeHour,
    businessHoursPerDay: opts.businessHours?.businessHoursPerDay,
    extraClosures: closureDateSet(closures),
  };

  const reportsDir = resolve(opts.outDir, SECTION889_REPORTS_DIRNAME);
  if (!existsSync(reportsDir)) mkdirSync(reportsDir, { recursive: true });
  const alreadyReported = readLedgerKeys(ledgerPath);

  const catalogSnapshotRef = {
    path: screen.catalog_snapshot_ref.path,
    sha256: screen.catalog_snapshot_ref.sha256,
    generated_at: screen.catalog_snapshot_ref.generated_at,
  };
  const sourceDigests = [
    { kind: 'w2-screen-envelope', path: relForProvenance(opts.outDir, screenPath), sha256: screenSha },
    { kind: 'contacts-yaml', path: relForProvenance(opts.outDir, contactsPath), sha256: existsSync(contactsPath) ? sha256Hex(readFileSync(contactsPath)) : '' },
  ];

  for (const match of reportable) {
    const contractsForMatch = affectedContracts(match, contacts);
    for (const contract of contractsForMatch) {
      const reportKind: Section889ReportKind = 'initial-1bd';
      const key: LedgerKey = { run_id: opts.runId, match_id: match.match_id, contract_number: contract.contractNumber, report_kind: reportKind };
      if (alreadyReported.has(ledgerKeyStr(key))) {
        result.reports_already_present += 1;
        continue;
      }

      const deadlineAt = deadlineFor(match.discovered_at, clockOpts);
      const remaining = businessHoursRemaining(emittedAt, deadlineAt, clockOpts);
      if (remaining <= 0) result.deadline_breached_at_emit += 1;

      const env = composeReportEnvelope({
        reportKind, match, contractNumber: contract.contractNumber,
        endpointType: contract.endpointType,
        contractingOfficerEmail: contract.contractingOfficerEmail,
        isSubcontractReport: contract.primeContractorUei !== null,
        primeContractorUei: contract.primeContractorUei,
        cspName: opts.cspName,
        cspUei: opts.cspUei?.trim() || REQUIRES_OPERATOR_INPUT,
        cspCageCode: opts.cspCageCode?.trim() || REQUIRES_OPERATOR_INPUT,
        runId: opts.runId,
        screenEnvelopePath: relForProvenance(opts.outDir, screenPath),
        screenEnvelopeSha256: screenSha,
        catalogSnapshotRef,
        discoveryKind: opts.discoveryKind ?? 'screen-run',
        federalBusinessHoursTz: tz,
        deadlineAt,
        businessHoursRemainingAtEmit: remaining,
        signingOfficer: { name: officerName, title: officerTitle, key_id: '', key_version: '' },
        waiverId: opts.waiverId ?? null,
        generatedAt: emittedAt,
        emittedAt,
        sourceDigests,
      });

      // ── Sign (detached Ed25519 over canonical signature-blanked bytes) ──
      const canonical = canonicalReportBytes(env);
      const sig = signDetached(Buffer.from(canonical, 'utf8'), opts.outDir);
      env.provenance.signingKeyId = sig.keyId;
      env.provenance.publicKeyPem = sig.publicKeyPem;
      env.provenance.signatureEd25519 = sig.signatureBase64;
      env.signing_officer.key_id = sig.keyId;
      env.signing_officer.key_version = sig.keyId;

      // ── Write JSON + .sig + .docx ──
      const jsonName = `${env.report_id}.json`;
      const jsonPath = resolve(reportsDir, jsonName);
      const jsonBytes = Buffer.from(JSON.stringify(env, null, 2), 'utf8');
      writeFileSync(jsonPath, jsonBytes);
      const sigPath = resolve(reportsDir, `${jsonName}.sig`);
      writeFileSync(sigPath, JSON.stringify({ algorithm: 'ed25519', keyId: sig.keyId, publicKeyPem: sig.publicKeyPem, sigBase64: sig.signatureBase64 }, null, 2));
      const docxPath = resolve(reportsDir, `${env.report_id}.docx`);
      writeFileSync(docxPath, renderSection889ReportDocx(env));

      // ── Ledger (idempotency substrate) ──
      appendFileSync(ledgerPath, JSON.stringify({
        ...key, report_id: env.report_id, vendor: env.far_d_2_i.supplier_name,
        deadline_at: deadlineAt, emitted_at: emittedAt, json_sha256: sha256Hex(jsonBytes),
        report_path_json: `${SECTION889_REPORTS_DIRNAME}/${jsonName}`,
        report_path_docx: `${SECTION889_REPORTS_DIRNAME}/${env.report_id}.docx`,
      }) + '\n');

      const pending = pendingOperatorFields(env);
      result.reports.push({
        report_id: env.report_id, report_kind: reportKind, contract_number: contract.contractNumber,
        vendor: env.far_d_2_i.supplier_name, json_path: jsonPath, sig_path: sigPath, docx_path: docxPath,
        deadline_at: deadlineAt, business_hours_remaining_at_emit: remaining, pending_operator_fields: pending,
      });
      result.reports_emitted += 1;
      result.follow_ups_scheduled += 1;

      const notification: Section889Notification = {
        kind: remaining <= 0 ? 'deadline-warning' : 'emitted',
        report_id: env.report_id, vendor: env.far_d_2_i.supplier_name,
        contract_number: contract.contractNumber, deadline_at: deadlineAt,
        business_hours_remaining: remaining,
        report_path_json: jsonPath, report_path_docx: docxPath,
      };
      try { notify(notification); } catch (e) { log.warn({ event: 'w.w3.notify_failed', err: String((e as Error)?.message ?? e) }); }
    }
  }

  augmentCoverage(opts.outDir, result);

  log.info({
    event: 'w.w3.reports_emitted', run_id: opts.runId,
    reportable_matches: result.reportable_matches, reports_emitted: result.reports_emitted,
    reports_already_present: result.reports_already_present, deadline_breached_at_emit: result.deadline_breached_at_emit,
  });
  return result;
}

/**
 * Compose a 10-business-day follow-up report (FAR 52.204-25(d)(2)(ii)) for an
 * already-emitted initial report. Pure composition + signing of one envelope;
 * the caller writes it. Exposed for the operator follow-up workflow + tests.
 */
export function composeFollowUpReport(opts: {
  outDir: string;
  initialReport: Section8891bdReport;
  followUp: FarD2iiContent;
  emittedAt?: string;
  federalBusinessHoursTz?: string;
  closures?: Set<string>;
  signingOfficer?: Section889SigningOfficer;
}): { envelope: Section8891bdReport; canonical: string } {
  const emittedAt = opts.emittedAt ?? new Date().toISOString();
  const tz = opts.federalBusinessHoursTz ?? opts.initialReport.federal_business_hours_tz ?? DEFAULT_BUSINESS_TZ;
  const followUpDeadline = followUpDeadlineFor(opts.initialReport.discovered_at, 10, { tz, extraClosures: opts.closures });
  const init = opts.initialReport;
  const env: Section8891bdReport = {
    ...init,
    report_id: reportIdFor(init.source_screen_envelope_ref.run_id, init.source_match_id, init.far_d_2_i.contract_number, 'follow-up-10bd'),
    report_kind: 'follow-up-10bd',
    generated_at: emittedAt,
    emitted_at: emittedAt,
    deadline_at: followUpDeadline,
    business_hours_remaining_at_emit: businessHoursRemaining(emittedAt, followUpDeadline, { tz, extraClosures: opts.closures }),
    far_d_2_ii: opts.followUp,
    source_initial_report_id: init.report_id,
    signing_officer: opts.signingOfficer ?? init.signing_officer,
    rfc3161_timestamp: { status: 'pending', tsa_url: null, token: null, received_at: null },
    provenance: { ...init.provenance, emittedAt, signingKeyId: '', publicKeyPem: '', signatureEd25519: '' },
  };
  const canonical = canonicalReportBytes(env);
  const sig = signDetached(Buffer.from(canonical, 'utf8'), opts.outDir);
  env.provenance.signingKeyId = sig.keyId;
  env.provenance.publicKeyPem = sig.publicKeyPem;
  env.provenance.signatureEd25519 = sig.signatureBase64;
  return { envelope: env, canonical };
}

function augmentCoverage(outDir: string, result: Section8891bdReportResult): void {
  const covPath = resolve(outDir, 'inventory-coverage.json');
  if (!existsSync(covPath)) return;
  try {
    const cov = JSON.parse(readFileSync(covPath, 'utf8'));
    cov.section889_1bd_coverage = {
      reportable_matches: result.reportable_matches,
      reports_emitted_this_run: result.reports_emitted,
      reports_already_present: result.reports_already_present,
      deadline_breached_at_emit: result.deadline_breached_at_emit,
      follow_ups_scheduled: result.follow_ups_scheduled,
    };
    writeFileSync(covPath, JSON.stringify(cov, null, 2));
  } catch (e) {
    log.warn({ event: 'w.w3.coverage_augment_failed', err: String((e as Error)?.message ?? e) });
  }
}

/** Verify a W.W3 report envelope's detached signature (for tests + 3PAO tooling). */
export function verifySection889Report(env: Section8891bdReport): boolean {
  if (!env.provenance?.signatureEd25519 || !env.provenance?.publicKeyPem) return false;
  return verifyDetached(Buffer.from(canonicalReportBytes(env), 'utf8'), {
    publicKeyPem: env.provenance.publicKeyPem,
    signatureBase64: env.provenance.signatureEd25519,
  });
}
