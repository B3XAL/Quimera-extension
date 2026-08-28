import assert from 'node:assert/strict';
import test from 'node:test';

import { fetchBurpScope } from '../interface/lib/quimera/bridgeClient.js';

test('scope client sends the pairing token and validates the versioned response', async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(
      JSON.stringify({
        schemaVersion: 1,
        hosts: ['app.example.test'],
        removedHosts: [],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };
  try {
    const result = await fetchBurpScope({
      bridgeEnabled: true,
      bridgePort: 8199,
      bridgeTokenEnabled: true,
      bridgeToken: 'a'.repeat(43),
    });
    assert.equal(request.url, 'http://127.0.0.1:8199/quimera/v1/scope');
    assert.equal(request.options.headers['X-Quimera-Token'], 'a'.repeat(43));
    assert.deepEqual(result, {
      status: 'ok',
      hosts: ['app.example.test'],
      removedHosts: [],
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('scope client refuses to communicate without a pairing token', async () => {
  const result = await fetchBurpScope({ bridgeEnabled: true });
  assert.equal(result.status, 'rejected');
  assert.match(result.error, /token/i);
});
