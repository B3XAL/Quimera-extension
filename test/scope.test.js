import assert from 'node:assert/strict';
import test from 'node:test';

import {
  normalizeScopeEntry,
  scopeEntryMatchesHost,
  scopeEntryOrigins,
} from '../interface/lib/quimera/scope.js';

test('scope normalization accepts exact and leading-wildcard domains only', () => {
  assert.equal(normalizeScopeEntry(' ZARA.COM '), 'zara.com');
  assert.equal(normalizeScopeEntry('*ZARA.COM'), '*zara.com');
  assert.equal(normalizeScopeEntry('zara*'), null);
  assert.equal(normalizeScopeEntry('*zara*'), null);
  assert.equal(normalizeScopeEntry('zara'), null);
  assert.equal(normalizeScopeEntry('localhost'), 'localhost');
  assert.equal(normalizeScopeEntry('*localhost'), null);
  assert.equal(normalizeScopeEntry('*127.0.0.1'), null);
});

test('leading wildcard matches apex and real subdomains without suffix confusion', () => {
  assert.equal(scopeEntryMatchesHost('*zara.com', 'zara.com'), true);
  assert.equal(scopeEntryMatchesHost('*zara.com', 'shop.zara.com'), true);
  assert.equal(scopeEntryMatchesHost('*zara.com', 'deep.shop.zara.com'), true);
  assert.equal(scopeEntryMatchesHost('*zara.com', 'evilzara.com'), false);
  assert.equal(scopeEntryMatchesHost('*zara.com', 'zara.com.evil.test'), false);
});

test('wildcard scope requests only apex and subdomain match patterns', () => {
  assert.deepEqual(scopeEntryOrigins('*zara.com'), [
    'http://zara.com/*',
    'https://zara.com/*',
    'http://*.zara.com/*',
    'https://*.zara.com/*',
  ]);
});
