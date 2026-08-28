/**
 * Shared constants for the Quimera additions to Cookie-Editor (Storage tab,
 * Vulns tab, and the optional bridge to the Quimera Burp extension).
 * Kept in one place so the popup, options page and background script agree
 * on the same storage key, message types and defaults.
 */

/** chrome.storage.local key holding the QuimeraOptions object. */
export const QUIMERA_STORAGE_KEY = 'quimera_options';

/** Privacy-preserving defaults. Collection and transmission require explicit opt-in. */
export const QUIMERA_DEFAULT_OPTIONS = {
  bridgeEnabled: false,
  bridgePort: 8199,
  bridgeTokenEnabled: true,
  bridgeToken: '',
  burpScopeSyncEnabled: false,
  manualScopeHosts: [],
  burpScopeHosts: [],
  burpScopePendingHosts: [],
  scopeHosts: [], // empty = capture nowhere
  collectors: {
    localStorage: true,
    sessionStorage: true,
    cookies: true,
    domSignals: true,
    postMessage: false,
    windowGlobals: true,
  },
};

/** Message types exchanged between content script, background and popup. */
export const MSG = {
  COLLECTED: 'quimeraCollected', // content -> background
  GET_SNAPSHOT: 'quimeraGetSnapshot', // popup -> background
  REQUEST_SNAPSHOT: 'quimeraRequestSnapshot', // background -> content (live refresh)
  GET_OPTIONS: 'quimeraGetOptions',
  SET_OPTIONS: 'quimeraSetOptions',
  PING_BRIDGE: 'quimeraPingBridge',
  SYNC_BURP_SCOPE: 'quimeraSyncBurpScope',
  AUTHORIZE_BURP_SCOPE: 'quimeraAuthorizeBurpScope',
};

export const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFORMATION: 3 };
