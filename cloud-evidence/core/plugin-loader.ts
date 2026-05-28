/**
 * Plugin architecture for custom KSI collectors.
 *
 * Use case:
 *   - Your org has KSIs the upstream catalog doesn't cover (e.g. a company-
 *     specific CNA-CUSTOM-XYZ that audits a homegrown service).
 *   - Or you want to OVERRIDE a built-in collector with a more-thorough
 *     implementation (e.g. cross-region check that the built-in skips).
 *
 * How:
 *   - Drop a `.ts` (or `.js`) file under `./plugins/` in the project root.
 *   - The file must `export default` a Plugin object (typed below).
 *   - On startup, the orchestrator scans `./plugins/` and loads each module.
 *   - Each plugin gets to register zero-or-more KSI entries with the KSI_MAP,
 *     ADDING (or REPLACING) entries. Replacements log a warning.
 *
 * Safety:
 *   - Plugins run with the same Node permissions as the orchestrator. The
 *     read-only guardrail still applies to AWS clients they construct via
 *     `core/auth/aws.ts` (because we wrap every client at construction time).
 *   - Plugins cannot bypass the schema validator — every emitted finding is
 *     still ajv-checked.
 *   - We DO NOT auto-load plugins by default. Set CLOUD_EVIDENCE_PLUGINS_DIR
 *     or pass --plugins-dir to opt in. This is defense-in-depth against
 *     supply-chain risk.
 *
 * Plugin manifest:
 *   The file's default export must satisfy the `Plugin` interface below.
 *   The orchestrator calls `plugin.register({ ksiMap })` and the plugin
 *   mutates the map.
 */
import { readdirSync, statSync, existsSync } from 'node:fs';
import { resolve, extname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { KSI_MAP, type KsiEntry } from './ksi-map.ts';
import { log } from './log.ts';

export interface PluginRegisterArgs {
  ksiMap: Record<string, KsiEntry>;
  /** Helper: register a KSI. Logs a warning if it replaces an existing one. */
  registerKsi: (entry: KsiEntry) => void;
}

export interface Plugin {
  /** Unique plugin name. */
  name: string;
  /** Semver-ish version string for the plugin. */
  version: string;
  /** Optional plugin description shown in startup logs. */
  description?: string;
  /** Called once at startup. Should register KSIs via args.registerKsi(). */
  register(args: PluginRegisterArgs): void | Promise<void>;
}

export interface PluginLoadResult {
  loaded: Array<{ name: string; version: string; path: string }>;
  failures: Array<{ path: string; error: string }>;
  registered_ksis: string[];
  replaced_ksis: string[];
}

function listPluginFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch (e: any) {
    // EACCES / ENOTDIR on the plugins dir is operator-actionable, not fatal —
    // log and continue with no plugins rather than crashing the whole run.
    log.warn({ event: 'plugins.dir_unreadable', dir, err_code: e?.code, err_message: e?.message });
    return [];
  }
  const out: string[] = [];
  for (const f of entries) {
    const p = resolve(dir, f);
    // A file can vanish between readdir and stat; treat stat failure as skip.
    let isFile = false;
    try { isFile = statSync(p).isFile(); } catch { continue; }
    if (!isFile) continue;
    if (!['.ts', '.mjs', '.js'].includes(extname(f))) continue;
    if (f.startsWith('_') || f.startsWith('.')) continue;
    if (f.endsWith('.test.ts') || f.endsWith('.test.js') || f.endsWith('.test.mjs')) continue;
    out.push(p);
  }
  return out.sort();
}

/**
 * Scan `pluginsDir` for plugin modules, dynamic-import each, and invoke
 * `register()`. Returns a structured result so the orchestrator can log a
 * summary line + bail if a critical plugin failed.
 *
 * Dynamic import means plugins can be ES modules OR CommonJS as long as
 * they expose a `default` export of the Plugin shape.
 */
export async function loadPlugins(pluginsDir: string): Promise<PluginLoadResult> {
  const result: PluginLoadResult = { loaded: [], failures: [], registered_ksis: [], replaced_ksis: [] };
  if (!pluginsDir) return result;

  const files = listPluginFiles(pluginsDir);
  if (files.length === 0) {
    log.debug({ event: 'plugins.empty_dir', dir: pluginsDir });
    return result;
  }

  for (const file of files) {
    try {
      const url = pathToFileURL(file).href;
      const mod = await import(url);
      const plugin: Plugin = mod.default ?? mod.plugin ?? mod;
      if (!plugin || typeof plugin.register !== 'function' || !plugin.name) {
        result.failures.push({ path: file, error: 'export default did not satisfy Plugin interface (must have { name, version, register })' });
        continue;
      }
      const registerKsi = (entry: KsiEntry) => {
        if (KSI_MAP[entry.id]) {
          result.replaced_ksis.push(entry.id);
          log.warn({ event: 'plugin.replacing_ksi', plugin: plugin.name, ksi: entry.id });
        } else {
          result.registered_ksis.push(entry.id);
        }
        KSI_MAP[entry.id] = entry;
      };
      await plugin.register({ ksiMap: KSI_MAP, registerKsi });
      result.loaded.push({ name: plugin.name, version: plugin.version, path: file });
      log.info({ event: 'plugin.loaded', name: plugin.name, version: plugin.version, path: file });
    } catch (e: any) {
      result.failures.push({ path: file, error: e?.message ?? String(e) });
      log.error({ event: 'plugin.load_failed', path: file, err_message: e?.message });
    }
  }
  return result;
}

/** Convenience: produce a one-line summary suitable for the orchestrator's console output. */
export function summarizePluginLoad(r: PluginLoadResult): string {
  if (r.loaded.length === 0 && r.failures.length === 0) return 'no plugins';
  const parts: string[] = [];
  parts.push(`${r.loaded.length} loaded`);
  if (r.registered_ksis.length > 0) parts.push(`+${r.registered_ksis.length} new KSI(s)`);
  if (r.replaced_ksis.length > 0) parts.push(`~${r.replaced_ksis.length} overridden`);
  if (r.failures.length > 0) parts.push(`${r.failures.length} failed`);
  return parts.join(', ');
}
