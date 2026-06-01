/**
 * Tests for core/readonly-guardrail-azure.ts.
 *
 * Verifies:
 *   1. Read-style Azure SDK methods (get*, list*, check*, …) pass through.
 *   2. Write-style methods (create*, update*, delete*, set*, patch*, …) throw.
 *   3. The Azure long-running operation prefix family (begin*, beginCreate*,
 *      beginDeleteAndWait, …) is reliably classified as write.
 *   4. Nested namespaces (subscriptions.list, resources.listByResourceGroup) are
 *      wrapped recursively.
 *   5. Symbols and internal props pass through untouched (PagedAsyncIterableIterator
 *      uses Symbol.asyncIterator).
 */
import { describe, it, expect } from 'vitest';
import { wrapAzureClient, ReadOnlyAzureViolationError, _internal } from '../../core/readonly-guardrail-azure.ts';

describe('Azure classify (prefix-based verb classifier)', () => {
  it('classifies read verbs as read', () => {
    for (const m of ['get', 'getByName', 'list', 'listByResourceGroup', 'listAll', 'check', 'checkNameAvailability', 'query', 'queryResources', 'next', 'byPage', 'export', 'exportTemplate', 'describe']) {
      expect(_internal.classify(m), m).toBe('read');
    }
  });

  it('classifies Azure long-running operation begin* methods as write', () => {
    for (const m of ['beginCreate', 'beginCreateOrUpdate', 'beginCreateOrUpdateAndWait', 'beginDelete', 'beginDeleteAndWait', 'beginUpdate', 'beginUpdateAndWait']) {
      expect(_internal.classify(m), m).toBe('write');
    }
  });

  it('classifies the standard write verbs as write', () => {
    for (const m of ['create', 'update', 'delete', 'patch', 'set', 'remove', 'insert', 'add', 'enable', 'disable', 'restore', 'regenerate', 'rotate', 'replace', 'restart', 'redeploy', 'failover', 'publish', 'install', 'upgrade']) {
      expect(_internal.classify(m), m).toBe('write');
    }
  });

  it('classifies unknown verbs as unknown (passthrough)', () => {
    // `resources` is the Resource Graph query method — a noun, no read prefix.
    expect(_internal.classify('resources')).toBe('unknown');
    expect(_internal.classify('foo')).toBe('unknown');
  });

  it('allows internal/symbol-ish names', () => {
    expect(_internal.classify('_internal')).toBe('read');
    expect(_internal.classify('sendRequest')).toBe('read'); // generic HTTP plumbing
  });
});

describe('wrapAzureClient', () => {
  it('allows getX / listX / checkX calls', async () => {
    const client = {
      async getSubscription(id: string) { return { id, ok: true }; },
      subscriptions: {
        async list() { return [{ id: 'sub-1' }]; },
      },
      async checkNameAvailability(_n: string) { return { available: true }; },
    };
    const wrapped = wrapAzureClient(client, 'test');
    expect(await wrapped.getSubscription('s')).toEqual({ id: 's', ok: true });
    expect(await wrapped.subscriptions.list()).toEqual([{ id: 'sub-1' }]);
    expect(await wrapped.checkNameAvailability('foo')).toEqual({ available: true });
  });

  it('blocks every long-running write begin* method', () => {
    const client = {
      virtualMachines: {
        beginCreateOrUpdateAndWait() { return Promise.resolve('mutated'); },
        beginDeleteAndWait() { return Promise.resolve('deleted'); },
      },
    };
    const wrapped = wrapAzureClient(client, 'compute');
    expect(() => wrapped.virtualMachines.beginCreateOrUpdateAndWait())
      .toThrow(ReadOnlyAzureViolationError);
    expect(() => wrapped.virtualMachines.beginDeleteAndWait())
      .toThrow(ReadOnlyAzureViolationError);
  });

  it('blocks every standard write verb', () => {
    const client = {
      keyVaults: {
        create() { return 'x'; },
        update() { return 'x'; },
        delete() { return 'x'; },
        regenerate() { return 'x'; },
        rotate() { return 'x'; },
      },
    };
    const wrapped = wrapAzureClient(client, 'kv');
    for (const m of ['create', 'update', 'delete', 'regenerate', 'rotate'] as const) {
      expect(() => (wrapped.keyVaults as any)[m]()).toThrow(ReadOnlyAzureViolationError);
    }
  });

  it('throws an Azure-flavored violation message that names the call path', () => {
    const client = { resources: { beginDelete() { /* */ } } };
    const wrapped = wrapAzureClient(client, 'arm');
    try {
      wrapped.resources.beginDelete();
      throw new Error('expected throw');
    } catch (e: any) {
      expect(e).toBeInstanceOf(ReadOnlyAzureViolationError);
      expect(e.message).toContain('arm.resources.beginDelete');
      expect(e.message).toContain('read-only');
    }
  });

  it('recursively wraps nested namespaces', async () => {
    const client = {
      a: { b: { c: { async getX() { return 1; }, beginDeleteX() { /* */ } } } },
    };
    const wrapped = wrapAzureClient(client, 'deep');
    expect(await wrapped.a.b.c.getX()).toBe(1);
    expect(() => wrapped.a.b.c.beginDeleteX()).toThrow(ReadOnlyAzureViolationError);
  });

  it('passes symbols and internal props through untouched', () => {
    const sym = Symbol('iter');
    const client: any = { [sym]: () => 'symbol-method', __internal: 'x' };
    const wrapped = wrapAzureClient(client, 't');
    expect(wrapped[sym]()).toBe('symbol-method');
    expect(wrapped.__internal).toBe('x');
  });

  it('does not interfere with non-function, non-object property reads', () => {
    const wrapped = wrapAzureClient({ name: 'azure-sub', count: 3, ok: true } as any, 't');
    expect((wrapped as any).name).toBe('azure-sub');
    expect((wrapped as any).count).toBe(3);
    expect((wrapped as any).ok).toBe(true);
  });
});
