/**
 * Firefox fallback for getting inject-mainworld.js to run in the page's own
 * JS world. Chromium gets there natively via manifest content_scripts
 * world:"MAIN" (see manifest.chrome.json); Firefox's MV3 support for that
 * key varies by version, so instead this isolated-world content script
 * (itself registered at document_start) injects inject-mainworld.js as a
 * classic <script src> tag, which always executes in the page's world
 * regardless of world: support. The target's CSP does not apply to a
 * script loaded from the extension's own moz-extension:// origin.
 */
(function () {
  'use strict';
  const api = typeof browser !== 'undefined' ? browser : chrome;
  const script = document.createElement('script');
  script.src = api.runtime.getURL('content/inject-mainworld.js');
  script.async = false;
  (document.head || document.documentElement).appendChild(script);
  script.addEventListener('load', () => script.remove());
})();
