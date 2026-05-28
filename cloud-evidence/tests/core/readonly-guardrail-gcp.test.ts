/**
 * Tests for core/readonly-guardrail-gcp.ts.
 *
 * Verifies:
 *   1. Read-style methods (get*, list*, search*, …) pass through.
 *   2. Write-style methods (create*, update*, delete*, set*, …) throw.
 *   3. Nested namespaces are wrapped recursively.
 *   4. Unknown verbs are permitted (we lean toward not breaking legit code,
 *      since GCP has read methods like `aggregatedList` that don't start
 *      with `get/list/search`).
 *   5. Symbols and internal props are passed through untouched.
 */
import { describe, it, expect } from 'vitest';
import { wrapGcpClient, ReadOnlyGcpViolationError, _internal } from '../../core/readonly-guardrail-gcp.ts';

describe('classify (prefix-based verb classifier)', () => {
  it('classifies read verbs as read', () => {
    for (const m of ['get', 'getProject', 'list', 'listInstances', 'search', 'searchAssets', 'export', 'exportAssets', 'recommend', 'recommendations', 'getIamPolicy', 'testIamPermissions']) {
      expect(_internal.classify(m), m).toBe('read');
    }
  });

  it('classifies write verbs as write', () => {
    for (const m of ['create', 'createBucket', 'update', 'updateInstance', 'delete', 'deleteSubnetwork', 'set', 'setIamPolicy', 'patch', 'insertInstance', 'add', 'addRole', 'enable', 'disableApi', 'remove', 'revoke', 'commit']) {
      expect(_internal.classify(m), m).toBe('write');
    }
  });

  it('classifies unknown verbs as unknown (passthrough)', () => {
    expect(_internal.classify('whatsThis')).toBe('unknown');
    expect(_internal.classify('foo')).toBe('unknown');
  });
});

describe('wrapGcpClient', () => {
  it('allows getX / listX / searchX calls', async () => {
    const client = {
      async getProject(name: string) { return { name, ok: true }; },
      async listInstances() { return [1, 2, 3]; },
      async searchAssets(q: string) { return { q, hits: [] }; },
    };
    const w = wrapGcpClient(client);
    expect((await w.getProject('p1')).name).toBe('p1');
    expect((await w.listInstances()).length).toBe(3);
    expect((await w.searchAssets('iam')).q).toBe('iam');
  });

  it('throws on a write call (deleteInstance)', () => {
    const client = {
      async deleteInstance(_name: string) { return { ok: true }; },
    };
    const w = wrapGcpClient(client);
    expect(() => (w as any).deleteInstance('inst-1')).toThrow(ReadOnlyGcpViolationError);
  });

  it('throws on setIamPolicy (privilege escalation surface)', () => {
    const client = {
      async setIamPolicy(_req: any) { return {}; },
    };
    const w = wrapGcpClient(client);
    expect(() => (w as any).setIamPolicy({})).toThrow(/setIamPolicy/);
  });

  it('recurses into nested namespaces (projects.serviceAccounts.list)', async () => {
    const inner = {
      async list() { return ['sa1', 'sa2']; },
      async delete(_id: string) { return {}; },
    };
    const middle = { serviceAccounts: inner };
    const client = { projects: middle };
    const w = wrapGcpClient(client);
    const out = await (w as any).projects.serviceAccounts.list();
    expect(out).toEqual(['sa1', 'sa2']);
    expect(() => (w as any).projects.serviceAccounts.delete('sa1')).toThrow(/delete/);
  });

  it('allows methods on the deny-list-exception (close, request, on, then)', () => {
    const client = {
      close() { return 'closed'; },
      request() { return 'sent'; },
      on(_e: string, _cb: any) { return this; },
      then(_cb: any) { return this; },
    };
    const w = wrapGcpClient(client);
    expect((w as any).close()).toBe('closed');
    expect((w as any).request()).toBe('sent');
    expect(() => (w as any).on('event', () => {})).not.toThrow();
  });

  it('passes plain data fields through', () => {
    const client = { projectId: 'p-123', region: 'us-central1' };
    const w = wrapGcpClient(client);
    expect((w as any).projectId).toBe('p-123');
    expect((w as any).region).toBe('us-central1');
  });

  it('passes private/symbol props through without classification', () => {
    const sym = Symbol('s');
    const client: any = { _internalState: { x: 1 }, [sym]: 'data' };
    const w = wrapGcpClient(client);
    expect(w._internalState.x).toBe(1);
    expect((w as any)[sym]).toBe('data');
  });

  it('blocks createX but allows createListStream (exception)', async () => {
    const client = {
      async createBucket(_n: string) { return {}; },
      createListStream() { return { stream: true }; },
    };
    const w = wrapGcpClient(client);
    expect(() => (w as any).createBucket('b')).toThrow(/createBucket/);
    expect((w as any).createListStream()).toEqual({ stream: true });
  });
});
