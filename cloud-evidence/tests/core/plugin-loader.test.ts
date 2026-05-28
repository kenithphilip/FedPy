/**
 * Tests for core/plugin-loader.ts — discovery, loading, KSI registration.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { loadPlugins, summarizePluginLoad } from '../../core/plugin-loader.ts';
import { KSI_MAP } from '../../core/ksi-map.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-plug-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function writePlugin(filename: string, src: string): void {
  writeFileSync(resolve(tmp, filename), src);
}

describe('loadPlugins', () => {
  it('returns empty result when the directory does not exist', async () => {
    const r = await loadPlugins('/nonexistent/path');
    expect(r.loaded).toEqual([]);
    expect(r.failures).toEqual([]);
  });

  it('returns empty result for an empty directory', async () => {
    const r = await loadPlugins(tmp);
    expect(r.loaded).toEqual([]);
  });

  it('loads a valid plugin and registers a new KSI', async () => {
    writePlugin('my-plugin.mjs', `
      const plugin = {
        name: 'test-plugin',
        version: '0.0.1',
        async register({ registerKsi }) {
          registerKsi({
            id: 'KSI-TEST-PLUGIN-NEW',
            name: 'Test',
            scope: 'CLOUD',
            statement: 'x',
            aws: async () => ({ provider: 'aws', evidence: [], findings: [] }),
          });
        },
      };
      export default plugin;
    `);
    const r = await loadPlugins(tmp);
    expect(r.loaded).toHaveLength(1);
    expect(r.loaded[0].name).toBe('test-plugin');
    expect(r.registered_ksis).toContain('KSI-TEST-PLUGIN-NEW');
    expect(KSI_MAP['KSI-TEST-PLUGIN-NEW']).toBeTruthy();
    // Clean up to avoid polluting other tests
    delete (KSI_MAP as any)['KSI-TEST-PLUGIN-NEW'];
  });

  it('flags replaced KSIs', async () => {
    // First, seed a KSI ID into KSI_MAP
    KSI_MAP['KSI-TEST-REPLACE'] = {
      id: 'KSI-TEST-REPLACE', name: 'Original', scope: 'CLOUD', statement: 'orig',
      aws: async () => ({ provider: 'aws', evidence: [], findings: [] }),
    };
    writePlugin('replacer.mjs', `
      export default {
        name: 'replacer',
        version: '1.0.0',
        register({ registerKsi }) {
          registerKsi({
            id: 'KSI-TEST-REPLACE',
            name: 'Replaced',
            scope: 'CLOUD',
            statement: 'replaced',
            aws: async () => ({ provider: 'aws', evidence: [], findings: [] }),
          });
        },
      };
    `);
    const r = await loadPlugins(tmp);
    expect(r.replaced_ksis).toContain('KSI-TEST-REPLACE');
    expect(KSI_MAP['KSI-TEST-REPLACE'].name).toBe('Replaced');
    delete (KSI_MAP as any)['KSI-TEST-REPLACE'];
  });

  it('records failures for plugins missing the Plugin interface', async () => {
    writePlugin('bad-shape.mjs', `export default { name: 'foo' };`);
    const r = await loadPlugins(tmp);
    expect(r.loaded).toHaveLength(0);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0].error).toMatch(/Plugin interface/);
  });

  it('records failures for plugins whose register() throws', async () => {
    writePlugin('thrower.mjs', `
      export default {
        name: 'thrower',
        version: '1.0',
        register() { throw new Error('register exploded'); },
      };
    `);
    const r = await loadPlugins(tmp);
    expect(r.loaded).toHaveLength(0);
    expect(r.failures[0].error).toMatch(/exploded/);
  });

  it('skips files starting with _ or . and test files', async () => {
    writePlugin('_helper.mjs', 'export default {};');
    writePlugin('.hidden.mjs', 'export default {};');
    writePlugin('my.test.mjs', 'export default {};');
    const r = await loadPlugins(tmp);
    expect(r.loaded.length + r.failures.length).toBe(0);
  });
});

describe('summarizePluginLoad', () => {
  it('returns "no plugins" when nothing loaded', () => {
    expect(summarizePluginLoad({ loaded: [], failures: [], registered_ksis: [], replaced_ksis: [] })).toBe('no plugins');
  });

  it('includes loaded count + new + overridden + failed', () => {
    const s = summarizePluginLoad({
      loaded: [{ name: 'a', version: '1', path: 'x' }, { name: 'b', version: '1', path: 'y' }],
      failures: [{ path: 'z', error: 'oops' }],
      registered_ksis: ['KSI-X'],
      replaced_ksis: ['KSI-Y', 'KSI-Z'],
    });
    expect(s).toContain('2 loaded');
    expect(s).toContain('+1 new');
    expect(s).toContain('~2 overridden');
    expect(s).toContain('1 failed');
  });
});
