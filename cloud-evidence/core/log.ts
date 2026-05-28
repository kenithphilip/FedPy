/**
 * Structured logging.
 *
 * Two output modes:
 *   - dev / local: pretty-printed lines via pino-pretty (default when stdout
 *     is a TTY)
 *   - production / CI: line-delimited JSON suitable for shipping to a SIEM
 *     (Datadog, OCSF, Splunk).
 *
 * Behavior is controlled by env vars:
 *   LOG_LEVEL        trace|debug|info|warn|error|fatal  (default: info)
 *   LOG_PRETTY       force pretty output (1) or JSON (0)
 *   LOG_FILE         if set, write JSON logs to this file as well as stderr
 *
 * The orchestrator should treat human-friendly console.log/console.error
 * output (the per-KSI progress lines) as the *user-visible* surface and
 * use this logger for everything else — collector internals, retry events,
 * schema validation, integration push diagnostics.
 *
 * Why both? The console lines must stay greppable, terse, and colourful for
 * an SRE running the script locally. The structured logger is for everything
 * future consumers (SIEM, audit pipeline, LLM ingestion) will care about.
 */
import pino, { type Logger, type LoggerOptions } from 'pino';

const LOG_LEVEL = (process.env.LOG_LEVEL ?? 'info').toLowerCase();
const PRETTY_FORCED = process.env.LOG_PRETTY;
const IS_TTY = process.stderr.isTTY === true;
const PRETTY =
  PRETTY_FORCED === '1' ? true :
  PRETTY_FORCED === '0' ? false :
  IS_TTY;

const baseOptions: LoggerOptions = {
  level: LOG_LEVEL,
  base: {
    app: 'cloud-evidence',
    pid: process.pid,
    hostname: undefined, // suppress hostname for cleanliness
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      // Don't ever leak these into logs even if the caller passes them
      'PARAMIFY_API_TOKEN',
      'TRACKER_API_TOKEN',
      'SLACK_WEBHOOK_URL',
      'PAGERDUTY_ROUTING_KEY',
      '*.password',
      '*.token',
      '*.api_token',
      '*.credentials',
    ],
    censor: '[redacted]',
  },
};

function buildLogger(): Logger {
  // pino's transport mechanism handles pretty + file in a worker thread,
  // which is the recommended ESM-friendly pattern.
  const targets: Array<Record<string, unknown>> = [];

  if (PRETTY) {
    targets.push({
      target: 'pino-pretty',
      level: LOG_LEVEL,
      options: {
        colorize: true,
        translateTime: 'SYS:HH:MM:ss.l',
        ignore: 'pid,hostname,app',
        singleLine: true,
        destination: 2, // stderr
      },
    });
  } else {
    targets.push({
      target: 'pino/file',
      level: LOG_LEVEL,
      options: { destination: 2 }, // stderr
    });
  }

  const logFile = process.env.LOG_FILE;
  if (logFile) {
    targets.push({
      target: 'pino/file',
      level: LOG_LEVEL,
      options: { destination: logFile, mkdir: true },
    });
  }

  // Cast: pino's TransportTargetOptions type is overly strict about the
  // `target`+`options` shape; our `targets` array conforms structurally but
  // the strict generic chokes. Verified at runtime by the log.test.ts suite.
  return pino({ ...baseOptions, transport: { targets } } as any);
}

export const log: Logger = buildLogger();

/** Create a child logger with stable context fields. */
export function logger(context: Record<string, unknown>): Logger {
  return log.child(context);
}

/**
 * Convenience: time an async operation and log start/end with duration.
 *
 *   await timed(log, 'iam.collect', { ksi: 'KSI-IAM-MFA' }, async () => {...});
 */
export async function timed<T>(
  base: Logger,
  event: string,
  ctx: Record<string, unknown>,
  fn: () => Promise<T>,
): Promise<T> {
  const child = base.child(ctx);
  const t0 = Date.now();
  child.debug({ event: `${event}.start` });
  try {
    const out = await fn();
    child.info({ event: `${event}.ok`, duration_ms: Date.now() - t0 });
    return out;
  } catch (err) {
    child.error({ event: `${event}.fail`, duration_ms: Date.now() - t0, err: serializeError(err) });
    throw err;
  }
}

function serializeError(e: unknown): Record<string, unknown> {
  if (!e) return { message: '<unknown>' };
  if (e instanceof Error) {
    return { name: e.name, message: e.message, stack: e.stack };
  }
  if (typeof e === 'object') return { ...e };
  return { message: String(e) };
}
