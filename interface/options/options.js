import { BrowserDetector } from '../lib/browserDetector.js';
import { Cookie } from '../lib/cookie.js';
import { GenericStorageHandler } from '../lib/genericStorageHandler.js';
import { JsonFormat } from '../lib/jsonFormat.js';
import { NetscapeFormat } from '../lib/netscapeFormat.js';
import { OptionsHandler } from '../lib/optionsHandler.js';
import { PermissionHandler } from '../lib/permissionHandler.js';
import { MSG, QUIMERA_DEFAULT_OPTIONS } from '../lib/quimera/constants.js';
import {
  normalizeScopeEntry,
  scopeEntryOrigins,
} from '../lib/quimera/scope.js';
import { ThemeHandler } from '../lib/themeHandler.js';
import { CookieHandlerPopup } from '../popup/cookieHandlerPopup.js';

document.addEventListener('DOMContentLoaded', async event => {
  const MAX_SCOPE_PERMISSION_BATCH = 50;
  const browserDetector = new BrowserDetector();
  const storageHandler = new GenericStorageHandler(browserDetector);
  const optionHandler = new OptionsHandler(browserDetector, storageHandler);
  const themeHandler = new ThemeHandler(optionHandler);
  const cookieHandler = new CookieHandlerPopup(browserDetector);
  const permissionHandler = new PermissionHandler(browserDetector);
  const advancedCookieInput = document.getElementById('advanced-cookie');
  const showDevtoolsInput = document.getElementById('devtool-show');
  const animationsEnabledInput = document.getElementById('animations-enabled');
  const exportFormatInput = document.getElementById('export-format');
  const extraInfoInput = document.getElementById('extra-info');
  const themeInput = document.getElementById('theme');
  const buttonBarTopInput = document.getElementById('button-bar-top');

  await optionHandler.loadOptions();
  themeHandler.updateTheme();
  setFormValues();
  optionHandler.on('optionsChanged', setFormValues);
  setInputEvents();
  initQuimeraBridgeOptions();

  /**
   * Wires up the "Quimera Bridge" section, kept independent from
   * Cookie-Editor's own OptionsHandler/Options class (separate storage key,
   * see interface/lib/quimera/constants.js) so it stays additive and
   * doesn't touch the existing options schema.
   */
  async function initQuimeraBridgeOptions() {
    const enabledInput = document.getElementById('quimera-bridge-enabled');
    const statusEl = document.getElementById('quimera-bridge-status');
    const checkButton = document.getElementById('quimera-bridge-check');
    const portInput = document.getElementById('quimera-bridge-port');
    const tokenEnabledInput = document.getElementById(
      'quimera-bridge-token-enabled'
    );
    const tokenInput = document.getElementById('quimera-bridge-token');
    tokenEnabledInput.disabled = true;
    const scopeInput = document.getElementById('quimera-scope-hosts');
    const globalAccessButton = document.getElementById(
      'quimera-grant-all-hosts'
    );
    const globalAccessStatus = document.getElementById(
      'quimera-global-access-status'
    );
    const burpSyncInput = document.getElementById('quimera-burp-scope-sync');
    const burpSyncButton = document.getElementById(
      'quimera-burp-scope-authorize'
    );
    const burpSyncStatus = document.getElementById('quimera-burp-scope-status');
    const collectorInputs = {
      localStorage: document.getElementById('quimera-collector-localStorage'),
      sessionStorage: document.getElementById(
        'quimera-collector-sessionStorage'
      ),
      cookies: document.getElementById('quimera-collector-cookies'),
      domSignals: document.getElementById('quimera-collector-domSignals'),
      postMessage: document.getElementById('quimera-collector-postMessage'),
      windowGlobals: document.getElementById('quimera-collector-windowGlobals'),
    };

    let current = await sendMessage(MSG.GET_OPTIONS);
    if (!current) current = QUIMERA_DEFAULT_OPTIONS;
    applyToForm(current);
    updateGlobalAccessStatus();
    checkBridgeStatus();

    enabledInput.addEventListener('change', save);
    portInput.addEventListener('change', () => {
      save();
      checkBridgeStatus();
    });
    tokenEnabledInput.addEventListener('change', save);
    tokenInput.addEventListener('change', save);
    scopeInput.addEventListener('change', save);
    globalAccessButton.addEventListener('click', grantGlobalAccess);
    burpSyncInput.addEventListener('change', save);
    burpSyncButton.addEventListener('click', syncAndAuthorizeBurpScope);
    checkButton.addEventListener('click', checkBridgeStatus);
    for (const input of Object.values(collectorInputs)) {
      input.addEventListener('change', save);
    }

    async function updateGlobalAccessStatus() {
      const granted = await permissionHandler.checkPermissions('<all_urls>');
      globalAccessButton.disabled = granted;
      globalAccessStatus.textContent = granted
        ? 'Access to all websites is granted. Quimera captures on every regular HTTP(S) page.'
        : 'Recommended: approve once to capture on every website without repeated host prompts.';
    }

    async function grantGlobalAccess() {
      const permissionRequest = { origins: ['<all_urls>'] };
      if (browserDetector.isFirefox()) {
        permissionRequest.data_collection = [
          'authenticationInfo',
          'browsingActivity',
          'websiteContent',
        ];
      }
      const granted = await browserDetector
        .getApi()
        .permissions.request(permissionRequest);
      await updateGlobalAccessStatus();
      if (!granted) return;
      await sendMessage(MSG.SET_OPTIONS, { options: current });
      burpSyncStatus.textContent =
        'Global access granted. Quimera now captures on all websites.';
      if (burpSyncInput.checked) {
        await sendMessage(MSG.SYNC_BURP_SCOPE);
        current = (await sendMessage(MSG.GET_OPTIONS)) || current;
        applyToForm(current);
      }
    }

    /** @param {object} opts */
    function applyToForm(opts) {
      enabledInput.checked = opts.bridgeEnabled;
      portInput.value = opts.bridgePort;
      tokenEnabledInput.checked = opts.bridgeTokenEnabled;
      tokenInput.value = opts.bridgeToken || '';
      scopeInput.value = (opts.manualScopeHosts || opts.scopeHosts || []).join(
        '\n'
      );
      burpSyncInput.checked = !!opts.burpScopeSyncEnabled;
      burpSyncStatus.textContent = opts.burpScopeSyncEnabled
        ? `${(opts.burpScopeHosts || []).length} Burp host(s) authorized; ${(opts.burpScopePendingHosts || []).length} pending.`
        : 'Synchronization disabled.';
      for (const [key, input] of Object.entries(collectorInputs)) {
        input.checked = opts.collectors ? opts.collectors[key] !== false : true;
      }
    }

    /** Reads the form and persists it via the background script. */
    async function save() {
      const collectors = {};
      for (const [key, input] of Object.entries(collectorInputs)) {
        collectors[key] = input.checked;
      }
      const requestedHosts = scopeInput.value
        .split('\n')
        .map(normalizeScopeEntry)
        .filter(Boolean);
      const origins = [...new Set(requestedHosts.flatMap(scopeEntryOrigins))];
      if (enabledInput.checked && tokenInput.value.trim().length < 32) {
        statusEl.textContent =
          'Paste the pairing token shown by the Quimera Burp extension first.';
        return false;
      }
      if (enabledInput.checked) origins.push('http://127.0.0.1/*');
      const hasGlobalAccess =
        await permissionHandler.checkPermissions('<all_urls>');
      if (origins.length && !hasGlobalAccess) {
        const permissionRequest = { origins };
        if (enabledInput.checked && browserDetector.isFirefox()) {
          permissionRequest.data_collection = [
            'authenticationInfo',
            'browsingActivity',
            'websiteContent',
          ];
        }
        const granted = await browserDetector
          .getApi()
          .permissions.request(permissionRequest);
        if (!granted) {
          statusEl.textContent =
            'Host permission was not granted; settings were not changed.';
          return false;
        }
      }
      const burpHosts = burpSyncInput.checked
        ? current.burpScopeHosts || []
        : [];
      const opts = {
        ...current,
        bridgeEnabled: enabledInput.checked,
        bridgePort: parseInt(portInput.value, 10) || 8199,
        bridgeTokenEnabled: true,
        bridgeToken: tokenInput.value.trim(),
        burpScopeSyncEnabled: burpSyncInput.checked,
        burpScopeHosts: burpHosts,
        burpScopePendingHosts: burpSyncInput.checked
          ? current.burpScopePendingHosts || []
          : [],
        manualScopeHosts: requestedHosts,
        scopeHosts: [...new Set([...requestedHosts, ...burpHosts])],
        collectors,
      };
      await sendMessage(MSG.SET_OPTIONS, { options: opts });
      current = opts;
      applyToForm(current);
      return true;
    }

    /** Fetches Burp candidates, requests permission, then commits only approved hosts. */
    async function syncAndAuthorizeBurpScope() {
      burpSyncStatus.textContent = 'Reading Burp Target Scope…';
      if (!(await save())) return;
      const result = await sendMessage(MSG.SYNC_BURP_SCOPE);
      if (!result?.success) {
        burpSyncStatus.textContent =
          result?.error || 'Could not read Burp Target Scope.';
        return;
      }
      const allPending = result.pendingHosts || [];
      const hasGlobalAccess =
        await permissionHandler.checkPermissions('<all_urls>');
      if (hasGlobalAccess && !allPending.length) {
        current = (await sendMessage(MSG.GET_OPTIONS)) || current;
        applyToForm(current);
        burpSyncStatus.textContent =
          'Burp scope synchronized using global website access.';
        return;
      }
      const pending = allPending.slice(0, MAX_SCOPE_PERMISSION_BATCH);
      if (!pending.length) {
        current = (await sendMessage(MSG.GET_OPTIONS)) || current;
        applyToForm(current);
        burpSyncStatus.textContent = 'Burp scope is already synchronized.';
        return;
      }
      const permissionRequest = {
        origins: [...new Set(pending.flatMap(scopeEntryOrigins))],
      };
      if (browserDetector.isFirefox()) {
        permissionRequest.data_collection = [
          'authenticationInfo',
          'browsingActivity',
          'websiteContent',
        ];
      }
      const granted = await browserDetector
        .getApi()
        .permissions.request(permissionRequest);
      if (!granted) {
        burpSyncStatus.textContent = `${pending.length} host(s) remain pending permission.`;
        return;
      }
      const authorized = await sendMessage(MSG.AUTHORIZE_BURP_SCOPE, {
        hosts: pending,
      });
      if (!authorized?.success) {
        burpSyncStatus.textContent =
          authorized?.error || 'Burp scope authorization failed.';
        return;
      }
      current = (await sendMessage(MSG.GET_OPTIONS)) || current;
      applyToForm(current);
      const remaining = authorized.pendingHosts.length;
      burpSyncStatus.textContent =
        authorized.authorizedHosts.length +
        ' Burp host(s) authorized; ' +
        remaining +
        ' pending' +
        (allPending.length > MAX_SCOPE_PERMISSION_BATCH
          ? ' (authorize the next batch).'
          : '.');
    }

    /** Pings the bridge and updates the status line. */
    async function checkBridgeStatus() {
      statusEl.textContent = 'Checking…';
      const result = await sendMessage(MSG.PING_BRIDGE);
      statusEl.textContent =
        result && result.connected
          ? 'Connected to Quimera'
          : 'Not connected (Quimera not running, or bridge disabled/blocked)';
    }

    /**
     * @param {string} type
     * @param {object} [params]
     * @return {Promise<any>}
     */
    function sendMessage(type, params) {
      return browserDetector.getApi().runtime.sendMessage({ type, ...params });
    }
  }

  /**
   * Sets the value of the form based on the saved options.
   */
  function setFormValues() {
    console.log('Setting up the form');
    handleAnimationsEnabled();
    advancedCookieInput.checked = optionHandler.getCookieAdvanced();
    showDevtoolsInput.checked = optionHandler.getDevtoolsEnabled();
    animationsEnabledInput.checked = optionHandler.getAnimationsEnabled();
    exportFormatInput.value = optionHandler.getExportFormat();
    extraInfoInput.value = optionHandler.getExtraInfo();
    themeInput.value = optionHandler.getTheme();
    buttonBarTopInput.checked = optionHandler.getButtonBarTop();
  }

  /**
   * Sets the different input listeners to save the form changes.
   */
  function setInputEvents() {
    advancedCookieInput.addEventListener('change', event => {
      if (!event.isTrusted) {
        return;
      }
      optionHandler.setCookieAdvanced(advancedCookieInput.checked);
    });
    showDevtoolsInput.addEventListener('change', event => {
      if (!event.isTrusted) {
        return;
      }
      optionHandler.setDevtoolsEnabled(showDevtoolsInput.checked);
    });
    animationsEnabledInput.addEventListener('change', event => {
      if (!event.isTrusted) {
        return;
      }
      optionHandler.setAnimationsEnabled(animationsEnabledInput.checked);
      handleAnimationsEnabled();
    });
    exportFormatInput.addEventListener('change', event => {
      if (!event.isTrusted) {
        return;
      }
      optionHandler.setExportFormat(exportFormatInput.value);
    });
    extraInfoInput.addEventListener('change', event => {
      if (!event.isTrusted) {
        return;
      }
      optionHandler.setExtraInfo(extraInfoInput.value);
    });
    themeInput.addEventListener('change', event => {
      if (!event.isTrusted) {
        return;
      }
      optionHandler.setTheme(themeInput.value);
      themeHandler.updateTheme();
    });
    buttonBarTopInput.addEventListener('change', event => {
      if (!event.isTrusted) {
        return;
      }
      optionHandler.setButtonBarTop(buttonBarTopInput.checked);
    });

    document
      .getElementById('delete-all')
      .addEventListener('click', async event => {
        await deleteAllCookies();
      });

    document
      .getElementById('export-all-json')
      .addEventListener('click', async event => {
        await exportCookiesAsJson();
      });

    document
      .getElementById('export-all-netscape')
      .addEventListener('click', async event => {
        await exportCookiesAsNetscape();
      });
  }

  /**
   * Get permissions for All urls.
   */
  async function getAllPermissions() {
    const hasPermissions =
      await permissionHandler.checkPermissions('<all_urls>');
    if (!hasPermissions) {
      await permissionHandler.requestPermission('<all_urls>');
    }
  }

  /**
   * Get all cookies for the browser
   */
  async function getAllCookies() {
    await getAllPermissions();
    const cookies = await cookieHandler.getAllCookiesInBrowser();
    const loadedCookies = {};
    for (const [index, cookie] of cookies.entries()) {
      const id = `${Cookie.hashCode(cookie)}_${index}`;
      loadedCookies[id] = new Cookie(id, cookie, optionHandler);
    }
    return loadedCookies;
  }

  /**
   * Delete all cookies.
   */
  async function deleteAllCookies() {
    const deleteAll = confirm(
      'Are you sure you want to delete ALL your cookies?'
    );
    if (!deleteAll) {
      return;
    }
    const cookies = await getAllCookies();
    for (const cookieId in cookies) {
      if (!Object.prototype.hasOwnProperty.call(cookies, cookieId)) {
        continue;
      }
      const exportedCookie = cookies[cookieId].cookie;
      const url = 'https://' + exportedCookie.domain + exportedCookie.path;
      await cookieHandler.removeCookie(exportedCookie.name, url);
    }
    alert('All your cookies were deleted');
  }

  /**
   * Export all cookies in the JSON format.
   */
  async function exportCookiesAsJson() {
    const cookies = await getAllCookies();
    copyText(JsonFormat.format(cookies));
    alert('Done!');
  }

  /**
   * Export all cookies in the Netscape format.
   */
  async function exportCookiesAsNetscape() {
    const cookies = await getAllCookies();
    copyText(NetscapeFormat.format(cookies));
    alert('Done!');
  }

  /**
   * Copy some text to the user's clipboard.
   * @param {string} text Text to copy.
   */
  function copyText(text) {
    const fakeText = document.createElement('textarea');
    fakeText.classList.add('clipboardCopier');
    fakeText.textContent = text;
    document.body.appendChild(fakeText);
    fakeText.focus();
    fakeText.select();
    // TODO: switch to clipboard API.
    document.execCommand('Copy');
    document.body.removeChild(fakeText);
  }

  /**
   * Enables or disables the animations based on the options.
   */
  function handleAnimationsEnabled() {
    if (optionHandler.getAnimationsEnabled()) {
      document.body.classList.remove('notransition');
    } else {
      document.body.classList.add('notransition');
    }
  }
});
