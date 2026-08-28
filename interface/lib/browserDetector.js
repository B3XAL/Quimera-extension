import { Browsers } from './browsers.js';
import { Env } from './env.js';

/**
 * Detects information about the browser being used.
 */
export class BrowserDetector {
  /**
   * Constructs the BrowserDetector.
   */
  constructor() {
    this.namespace =
      (typeof browser !== 'undefined' ? browser : null) ||
      (typeof chrome !== 'undefined' ? chrome : null) ||
      (typeof window !== 'undefined' ? window.browser || window.chrome : null);
    this.supportSidePanel = false;

    try {
      this.supportSidePanel = typeof this.getApi().sidePanel !== 'undefined';
      console.info('SidePanel support: ', this.supportSidePanel);
    } catch (e) {
      /* empty */
    }

    if (Env.browserName === '@@browser_name') {
      // The release build replaces this placeholder per target. When source is loaded unpacked,
      // detect the real browser at runtime instead of blindly assuming Chrome,
      // otherwise isFirefox()/isSafari() below always return false even ON Firefox/Safari,
      // silently breaking their few browser-specific branches (Firefox devtools permission
      // message, Firefox/Safari Android/iOS mobile popup, Safari's cookies.onChanged skip).
      Env.browserName = BrowserDetector.detectBrowserNameAtRuntime();
    }
  }

  /**
   * Get the main API container specific to the current browser.
   * @return {chrome|browser}
   */
  getApi() {
    return this.namespace;
  }

  /**
   * Checks if the current browser is Firefox.
   * @return {boolean} true if the current browser is Firefox, otherwise false.
   */
  isFirefox() {
    return Env.browserName === Browsers.Firefox;
  }

  /**
   * Checks if the current browser is Chrome.
   * @return {boolean} true if the current browser is Chrome, otherwise false.
   */
  isChrome() {
    return Env.browserName === Browsers.Chrome;
  }

  /**
   * Checks if the current browser is Edge.
   * @return {boolean} true if the current browser is Edge, otherwise false.
   */
  isEdge() {
    return Env.browserName === Browsers.Edge;
  }

  /**
   * Checks if the current browser is Safari.
   * @return {boolean} true if the current browser is Safari, otherwise false.
   */
  isSafari() {
    return Env.browserName === Browsers.Safari;
  }

  /**
   * Checks if the current browser supports the Sidepanel API.
   * @return {boolean} true if the current browser supports the Sidepanel API,
   *     otherwise false.
   */
  supportsSidePanel() {
    return this.supportSidePanel;
  }

  /**
   * Gets the current browser name.
   * @return {string} The browser name.
   */
  getBrowserName() {
    return Env.browserName;
  }

  /**
   * Overrides the detected browser name.
   * @param {string} browserName The new browser name to set.
   */
  overrideBrowserName(browserName) {
    Env.browserName = browserName;
  }

  /**
   * Best-effort runtime detection of which browser this is, used only as a fallback when the
   * build-time '@@browser_name' placeholder was never substituted (no build step, see the
   * constructor). Namespace presence narrows it to the Firefox/Safari family (both expose the
   * promise-based `browser.*` API) vs. the Chromium family (`chrome.*` only), then the User-Agent
   * string (available in every context an extension runs in, including MV3 service workers)
   * narrows further. Good enough to make isFirefox()/isSafari()/isEdge() correct without pulling
   * in a real UA-parsing dependency, this project ships dependency-free on purpose.
   * @return {string} one of the Browsers enum values.
   */
  static detectBrowserNameAtRuntime() {
    const ua = (typeof navigator !== 'undefined' && navigator.userAgent) || '';
    const hasPromiseNamespace = typeof browser !== 'undefined';

    if (hasPromiseNamespace) {
      if (/Firefox\//.test(ua)) return Browsers.Firefox;
      if (/Safari\//.test(ua) && !/Chrom(e|ium)\//.test(ua))
        return Browsers.Safari;
      // Some other browser.* implementer we don't specifically brand for, Firefox is the closest
      // behavioral match (Manifest V3 quirks-wise) among the promise-namespace family.
      return Browsers.Firefox;
    }

    if (/Edg\//.test(ua)) return Browsers.Edge;
    if (/OPR\//.test(ua)) return Browsers.Opera;
    return Browsers.Chrome;
  }
}
