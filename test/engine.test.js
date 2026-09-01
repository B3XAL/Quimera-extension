import assert from 'node:assert/strict';
import test from 'node:test';

await import('../content/engine.js');

const { analyze, looksLikeOpaqueToken } = globalThis.QuimeraEngine;

test('opaque-token detection rejects absolute and relative application routes', () => {
  assert.equal(looksLikeOpaqueToken('/Account/ResetPassword'), false);
  assert.equal(looksLikeOpaqueToken('users/unlock-user'), false);
  assert.equal(looksLikeOpaqueToken('account/reset/password'), false);
});

test('opaque-token detection retains credential-shaped values', () => {
  assert.equal(looksLikeOpaqueToken('abcDEF0123456789_xyz'), true);
  assert.equal(looksLikeOpaqueToken('YWJjZGVmZ2hpL2tsbW5vcA=='), true);
});

test('storage detection reports a UUID userId as identifying data, not auth', () => {
  const findings = analyze({
    localStorage: {
      userId: '6189784b-fc8b-cdcd-85f7-704db4ab7831',
    },
    sessionStorage: {},
    dom: {},
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, 'storage');
  assert.equal(findings[0].severity, 'MEDIUM');
  assert.match(findings[0].title, /Identifying data stored in localStorage/);
  assert.match(findings[0].evidence, /localStorage\.userId/);
});

test('storage detection covers nested identifying fields and UUIDs under generic keys', () => {
  const findings = analyze({
    localStorage: {
      profile: JSON.stringify({
        email: 'julen@example.test',
        displayName: 'Julen Garrido',
      }),
      componentId: '6189784b-fc8b-cdcd-85f7-704db4ab7831',
    },
    sessionStorage: {},
    dom: {},
  });

  assert.equal(findings.length, 3);
  assert.ok(findings.every(f => f.category === 'storage'));
  assert.ok(findings.some(f => f.evidence.includes('componentId')));
});

test('JWT storage exposure is medium in localStorage and low in sessionStorage', () => {
  const jwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    'eyJzdWIiOiI1MDE1YzM2Zi0zZDg1LTRmNzMtYmY2ZC0zMmI3MDhjMzllMmIiLCJleHAiOjE3ODgzNDg4NDl9.' +
    'Gcu5i42dLKni2jjTZ_ZoM-9Dfwag_ezwbqP9GrtS8f0';
  const findings = analyze({
    localStorage: { lw_token: jwt },
    sessionStorage: { lw_token: jwt },
    dom: {},
  });

  assert.ok(
    findings.some(
      f =>
        f.title.startsWith('JWT stored in localStorage') &&
        f.severity === 'MEDIUM'
    )
  );
  assert.ok(
    findings.some(
      f =>
        f.title.startsWith('JWT stored in sessionStorage') &&
        f.severity === 'LOW'
    )
  );
  assert.ok(
    findings
      .filter(f => f.title.includes('localStorage'))
      .every(f => ['HIGH', 'MEDIUM'].includes(f.severity))
  );
  assert.ok(
    findings
      .filter(f => f.title.includes('sessionStorage'))
      .every(f => ['HIGH', 'MEDIUM', 'LOW'].includes(f.severity))
  );
});
