import assert from 'node:assert/strict';
import test from 'node:test';

import {
  authorizePendingBurpHosts,
  reconcileBurpScope,
} from '../interface/lib/quimera/scopeSync.js';

test('Burp synchronization adds candidates without silently authorizing them', () => {
  const options = {
    manualScopeHosts: ['*manual.test'],
    burpScopeHosts: ['old.test'],
    burpScopePendingHosts: [],
  };
  const updated = reconcileBurpScope(options, [
    'api.manual.test',
    'new.test',
    'old.test',
  ]);

  assert.deepEqual(updated.burpScopeHosts, ['old.test']);
  assert.deepEqual(updated.burpScopePendingHosts, ['new.test']);
  assert.deepEqual(updated.scopeHosts, ['*manual.test', 'old.test']);
});

test('authorization commits only authenticated pending candidates', () => {
  const options = {
    manualScopeHosts: [],
    burpScopeHosts: [],
    burpScopePendingHosts: ['approved.test'],
  };
  const updated = authorizePendingBurpHosts(options, [
    'approved.test',
    'injected.test',
  ]);

  assert.deepEqual(updated.burpScopeHosts, ['approved.test']);
  assert.deepEqual(updated.burpScopePendingHosts, []);
  assert.deepEqual(updated.scopeHosts, ['approved.test']);
});

test('explicit Burp removals disable synchronized collectors but preserve manual scope', () => {
  const options = {
    manualScopeHosts: ['manual.test'],
    burpScopeHosts: ['keep.test', 'remove.test'],
    burpScopePendingHosts: ['pending.test'],
  };
  const updated = reconcileBurpScope(
    options,
    ['keep.test'],
    ['remove.test', 'pending.test']
  );

  assert.deepEqual(updated.burpScopeHosts, ['keep.test']);
  assert.deepEqual(updated.burpScopePendingHosts, []);
  assert.deepEqual(updated.scopeHosts, ['manual.test', 'keep.test']);
});
