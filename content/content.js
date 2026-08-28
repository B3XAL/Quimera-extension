/**
 * Quimera's passive collector. Classic content script (isolated world),
 * loaded after engine.js in the manifest so `window.QuimeraEngine` is
 * already defined. It only collects on hosts explicitly authorized by the
 * user; an empty scope means collection is disabled.
 *
 * The handful of constants below are duplicated from
 * interface/lib/quimera/constants.js rather than dynamically import()-ed
 * from it. This used to be a dynamic import, which is exactly what broke
 * silently once already (a missing web_accessible_resources entry made
 * every single page's collection fail with an uncaught promise rejection,
 * invisible unless you had devtools open). Passive, automatic collection
 * on every page is the whole point of this file, it must not depend on a
 * cross-context resource fetch succeeding just to get started. Keep these
 * three values in sync with constants.js by hand if either ever changes,
 * it's three string literals, not worth a build step to avoid duplicating.
 */
(function () {
  'use strict';

  const MSG = {
    COLLECTED: 'quimeraCollected',
    REQUEST_SNAPSHOT: 'quimeraRequestSnapshot',
  };
  const QUIMERA_STORAGE_KEY = 'quimera_options';
  const QUIMERA_DEFAULT_OPTIONS = {
    scopeHosts: [],
    collectors: {
      localStorage: true,
      sessionStorage: true,
      cookies: true,
      domSignals: true,
    },
  };

  const MAINWORLD_TAG = '__quimera_mainworld__';
  // Caps what feeds the local vuln engine and the (optional) Burp bridge
  // payload only, NOT what the Storage tab lets you view/edit, that always
  // re-reads the real, complete, live value on demand (see quimera-tabs.js
  // readStorageItem). 64 KB comfortably covers real-world large single
  // values (OIDC/MSAL-style auth state objects bundling full JWTs plus a
  // JWKS key set commonly run several KB) while still bounding a
  // pathological single entry (some apps cache MB-scale blobs).
  const MAX_STORAGE_VALUE_LEN = 65536;
  const MAX_STORAGE_KEYS = 500;

  // Web Storage keys written by Burp's OWN embedded browser tooling, not by the application under
  // test. When testing through Burp's built-in Chromium (or any browser with DOM Invader active),
  // these show up on every single page and are pure noise, not app data, so they're excluded at
  // the collection point: never shown in the Storage tab, never fed to the Vulns engine, never
  // sent to the bridge. Case-insensitive exact match (not a substring check) so a real app key
  // that merely contains one of these words as part of a longer name is never suppressed by
  // accident.
  const BURP_TOOLING_STORAGE_KEYS = new Set(['dominvadersettings']);

  function isBurpToolingKey(key) {
    return BURP_TOOLING_STORAGE_KEYS.has((key || '').toLowerCase());
  }

  const api = typeof browser !== 'undefined' ? browser : chrome;

  let mainWorldData = { windowGlobals: [] };
  window.addEventListener('message', e => {
    if (!e.data || e.data.tag !== MAINWORLD_TAG) return;
    mainWorldData = { windowGlobals: e.data.windowGlobals || [] };
  });

  /** Dumps a Storage object (localStorage/sessionStorage) as plain object, capped. */
  function dumpStorage(storage) {
    const out = {};
    try {
      const len = Math.min(storage.length, MAX_STORAGE_KEYS);
      for (let i = 0; i < len; i++) {
        const key = storage.key(i);
        if (key === null || isBurpToolingKey(key)) continue;
        let value = storage.getItem(key);
        if (typeof value === 'string' && value.length > MAX_STORAGE_VALUE_LEN) {
          value = value.slice(0, MAX_STORAGE_VALUE_LEN);
        }
        out[key] = value;
      }
    } catch (e) {
      /* storage can throw in sandboxed/opaque-origin frames, skip silently */
    }
    return out;
  }

  /** Rendered-DOM signals: just the window-globals snapshot reported by
   * inject-mainworld.js, passed through under `dom` for engine.js. Insecure-
   * form scanning and generic hidden-input/HTML-comment secret scanning used
   * to live here too, removed along with the engine.js checks that consumed
   * them, neither is a headers/cookies/auth finding, see analyzeDomSignals
   * in engine.js for the full reasoning. (target=_blank/noopener scanning
   * was removed earlier for a related reason: every current-generation
   * browser sets noopener implicitly by default, so it isn't a live issue.) */
  function collectDomSignals() {
    return { windowGlobals: mainWorldData.windowGlobals };
  }

  /** Builds the full payload + runs the local engine over it. */
  function collect(options, reason) {
    const collectors = {
      ...QUIMERA_DEFAULT_OPTIONS.collectors,
      ...(options?.collectors || {}),
    };
    const payload = {
      schemaVersion: 2,
      snapshotReason: reason || 'manual',
      origin: location.origin,
      href: location.href,
      host: location.host,
      path: location.pathname,
      documentTitle: document.title,
      timestamp: new Date().toISOString(),
      localStorage: collectors.localStorage
        ? dumpStorage(window.localStorage)
        : {},
      sessionStorage: collectors.sessionStorage
        ? dumpStorage(window.sessionStorage)
        : {},
      jsCookieNames: collectors.cookies
        ? (document.cookie || '')
            .split(';')
            .map(c => c.split('=')[0].trim())
            .filter(Boolean)
        : [],
      dom: collectors.domSignals ? collectDomSignals() : { windowGlobals: [] },
    };
    const findings = window.QuimeraEngine
      ? window.QuimeraEngine.analyze(payload)
      : [];
    return { payload, findings };
  }

  async function getOptions() {
    try {
      const stored = await api.storage.local.get([QUIMERA_STORAGE_KEY]);
      return {
        ...QUIMERA_DEFAULT_OPTIONS,
        ...(stored[QUIMERA_STORAGE_KEY] || {}),
      };
    } catch (e) {
      return QUIMERA_DEFAULT_OPTIONS;
    }
  }

  let lastFingerprint = '';
  async function collectAndSend(reason) {
    const options = await getOptions();
    const scopeHosts = options.scopeHosts || [];
    const currentHost = location.hostname.toLowerCase();
    const inScope = scopeHosts.some(entry => {
      const normalized = String(entry || '').toLowerCase();
      if (!normalized.startsWith('*')) return currentHost === normalized;
      const base = normalized.slice(1);
      return currentHost === base || currentHost.endsWith(`.${base}`);
    });
    if (!scopeHosts.length || !inScope) {
      return;
    }
    const { payload, findings } = collect(options, reason);
    const fingerprint = JSON.stringify({
      ...payload,
      timestamp: undefined,
      snapshotReason: undefined,
    });
    if (fingerprint === lastFingerprint) return;
    lastFingerprint = fingerprint;
    try {
      await api.runtime.sendMessage({ type: MSG.COLLECTED, payload, findings });
    } catch (e) {
      // Background not reachable (extension reloading/updating mid-navigation, the one remaining
      // failure mode here since constants are inlined above, not fetched). Transient and self-
      // healing: the next page load/navigation retries this from scratch, so it's fine for this
      // one to stay quiet rather than surface a UI warning for what's normally a one-off blip.
      console.warn(
        '[Quimera] could not deliver collected snapshot to background',
        e
      );
    }
  }

  // Automatic passive capture: wait a beat after document_idle so the
  // main-world hook (loaded at document_start) has had a chance to report,
  // and SPA hydration has settled a little.
  setTimeout(() => collectAndSend('page-load'), 1500);

  let eventTimer;
  function schedule(reason) {
    clearTimeout(eventTimer);
    eventTimer = setTimeout(() => collectAndSend(reason), 750);
  }
  window.addEventListener('storage', () => schedule('storage-change'));
  window.addEventListener('pageshow', () => schedule('pageshow'));
  window.addEventListener('hashchange', () => schedule('navigation'));
  window.addEventListener('popstate', () => schedule('navigation'));
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') schedule('visible');
  });
  setInterval(() => collectAndSend('periodic'), 30000);

  // On-demand fresh snapshot for the popup's Storage/Vulns tabs.
  api.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === MSG.REQUEST_SNAPSHOT) {
      getOptions().then(options => sendResponse(collect(options, 'manual')));
      return true;
    }
  });
})();
