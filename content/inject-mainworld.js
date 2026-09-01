/**
 * Runs in the PAGE's own JS world (world: "MAIN"), not the content script's
 * isolated world, so it can see the page's own globals. Must load at
 * document_start so it's in place before the page's own scripts run.
 *
 * Talks back to content.js (isolated world) via window.postMessage with a
 * unique, unguessable-enough type tag so it's never confused with the
 * page's own postMessage traffic.
 *
 * Used to also hook window.addEventListener to flag postMessage listeners
 * that never check event.origin, removed along with the engine.js check
 * that consumed it: not a headers/cookies/auth finding, see engine.js's
 * analyzeDomSignals for the full reasoning. No reason to keep patching a
 * page global (real, if narrow, risk of breaking a page's own message
 * handling) for a signal nothing reads anymore.
 */
(function () {
  'use strict';

  // Idempotency guard: on Chromium this file is loaded natively via
  // manifest content_scripts world:"MAIN". On Firefox (which doesn't
  // support that key) it's instead loaded by mainworld-loader.js injecting
  // a <script src> tag. Nothing loads it both ways on the same browser
  // today, but the guard is cheap insurance against double-running this.
  if (window.__quimeraMainworldInjected) return;
  window.__quimeraMainworldInjected = true;

  const TAG = '__quimera_mainworld__';

  /** Grabs top-level window globals whose name looks credential-related. */
  function collectSensitiveGlobals() {
    const SENSITIVE =
      /token|jwt|session|sessid|auth|secret|password|passwd|credential|apikey|api_key/i;
    const out = [];
    const baseline = new Set([
      'window',
      'self',
      'top',
      'parent',
      'frames',
      'document',
      'location',
      'navigator',
      'history',
      'screen',
      'console',
      'chrome',
      'browser',
    ]);
    let count = 0;
    for (const name of Object.getOwnPropertyNames(window)) {
      if (count >= 200) break; // safety cap, pathological pages can have huge globals
      if (
        baseline.has(name) ||
        name.startsWith('webkit') ||
        name.startsWith('on')
      )
        continue;
      if (!SENSITIVE.test(name)) continue;
      let value;
      try {
        value = window[name];
      } catch (e) {
        continue;
      }
      if (typeof value !== 'string' || !value) continue;
      count++;
      out.push({ name, value: value.slice(0, 2048) });
    }
    return out;
  }

  // Give the page a beat to register its own globals before reporting back
  // (document_start means the DOM/app JS hasn't run yet).
  window.addEventListener('load', report, { once: true });
  // Also report shortly after in case the page never fires 'load' cleanly
  // (some SPAs), so the isolated-world side always gets a snapshot.
  setTimeout(report, 2500);

  let reported = false;
  function report() {
    if (reported) return;
    reported = true;
    window.postMessage(
      {
        tag: TAG,
        windowGlobals: collectSensitiveGlobals(),
      },
      '*'
    );
  }
})();
