import { BrowserDetector } from './interface/lib/browserDetector.js';
import { Browsers } from './interface/lib/browsers.js';
import { PermissionHandler } from './interface/lib/permissionHandler.js';
import {
  fetchBurpScope,
  pingBridge,
  sendToBridge,
} from './interface/lib/quimera/bridgeClient.js';
import {
  MSG,
  QUIMERA_DEFAULT_OPTIONS,
  QUIMERA_STORAGE_KEY,
  SEVERITY_ORDER,
} from './interface/lib/quimera/constants.js';
import { analyzeCookies } from './interface/lib/quimera/cookieChecks.js';
import {
  authorizePendingBurpHosts,
  reconcileBurpScope,
} from './interface/lib/quimera/scopeSync.js';

(async function () {
  console.log('starting background script');
  // TODO: Separate connections from CookieHandler and OptionsHandler.
  // It would also be cool to separate their whole behavior in separate class
  // that extends a generic one.
  const connections = {};
  const browserDetector = new BrowserDetector();
  const permissionHandler = new PermissionHandler(browserDetector);

  // Quimera additions: per-tab live snapshot cache (Storage/Vulns popup
  // tabs and the bridge to the Quimera Burp extension). In-memory only, on
  // purpose, cleared on browser/extension restart same as everything else
  // Cookie-Editor keeps in the background script.
  const quimeraSnapshots = {};

  // Same severity colors Quimera's own Burp UI uses (model/Severity.java),
  // so the badge and the Vulns tab agree visually on what "bad" looks like.
  const BADGE_COLOR_BY_SEVERITY = {
    HIGH: '#c0392b',
    MEDIUM: '#d37f00',
    LOW: '#27ae60',
  };

  /**
   * Sets the toolbar icon's badge for one tab to the count of non-
   * INFORMATION findings on it (routine inventory notes like "JWT
   * detected" don't need to visually shout on every page), colored by the
   * worst severity present. Clears the badge entirely when there's nothing
   * to flag, per-tab so switching tabs shows the right count automatically.
   * @param {number} tabId
   * @param {Array<object>} findings
   */
  function updateBadge(tabId, findings) {
    const actionable = (findings || []).filter(
      f => f.severity && f.severity !== 'INFORMATION'
    );
    if (actionable.length === 0) {
      browserDetector.getApi().action.setBadgeText({ tabId, text: '' });
      return;
    }
    const worst = actionable.reduce((a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) <= (SEVERITY_ORDER[b.severity] ?? 9)
        ? a
        : b
    );
    browserDetector
      .getApi()
      .action.setBadgeText({ tabId, text: String(actionable.length) });
    browserDetector.getApi().action.setBadgeBackgroundColor({
      tabId,
      color: BADGE_COLOR_BY_SEVERITY[worst.severity] || '#777777',
    });
  }

  /** @return {Promise<object>} the saved QuimeraOptions, or the defaults. */
  async function getQuimeraOptions() {
    const stored = await browserDetector
      .getApi()
      .storage.local.get([QUIMERA_STORAGE_KEY]);
    const options = {
      ...QUIMERA_DEFAULT_OPTIONS,
      ...(stored[QUIMERA_STORAGE_KEY] || {}),
    };
    if (!stored[QUIMERA_STORAGE_KEY]?.manualScopeHosts) {
      options.manualScopeHosts = options.scopeHosts || [];
    }
    return options;
  }

  async function storeQuimeraOptions(options) {
    await browserDetector
      .getApi()
      .storage.local.set({ [QUIMERA_STORAGE_KEY]: options });
  }

  let contentScriptSyncQueue = Promise.resolve();

  /** Serializes collector registration: a permission event and an Options save can arrive together. */
  function syncQuimeraContentScripts(options) {
    const next = contentScriptSyncQueue
      .catch(() => {})
      .then(() => performContentScriptSync(options));
    contentScriptSyncQueue = next;
    return next;
  }

  /** Keeps collectors registered for global access or explicitly authorized hosts. */
  async function performContentScriptSync(options) {
    const api = browserDetector.getApi();
    // Remove registrations left by older builds. Collectors are now declared statically in each
    // manifest, so browser host permissions alone control injection and no worker/scope state can
    // suppress an authorized page.
    const ids = ['quimera-main-world', 'quimera-collector'];
    try {
      await api.scripting.unregisterContentScripts({ ids });
    } catch (error) {
      // No previous registrations (or an older engine); registration below is still attempted.
    }
    const hasGlobalAccess = await api.permissions.contains({
      origins: ['<all_urls>'],
    });
    if (options.captureAllHosts !== hasGlobalAccess) {
      options = { ...options, captureAllHosts: hasGlobalAccess };
      await storeQuimeraOptions(options);
    }
  }

  async function notifyCollectorsToRetry() {
    const tabs = await browserDetector.getApi().tabs.query({});
    await Promise.allSettled(
      tabs
        .filter(tab => tab.id !== undefined)
        .map(tab =>
          browserDetector
            .getApi()
            .tabs.sendMessage(tab.id, { type: MSG.RETRY_DELIVERY })
        )
    );
  }

  async function applyQuimeraOptions(options) {
    await storeQuimeraOptions(options);
    await syncQuimeraContentScripts(options);
    if (options.burpScopeSyncEnabled) {
      browserDetector
        .getApi()
        .alarms.create('quimera-burp-scope-sync', { periodInMinutes: 1 });
    } else {
      await browserDetector.getApi().alarms.clear('quimera-burp-scope-sync');
    }
    if (options.bridgeEnabled) await notifyCollectorsToRetry();
    return { success: true };
  }

  function scopeResultError(result) {
    if (result.status === 'disabled')
      return 'Enable and pair the Burp bridge first.';
    if (result.status === 'unreachable')
      return 'Quimera Burp is not reachable.';
    return result.error || 'Burp scope synchronization failed.';
  }

  async function refreshBurpScope(options) {
    if (!options.burpScopeSyncEnabled) {
      const updated = {
        ...options,
        burpScopePendingHosts: [],
        scopeHosts: [...new Set(options.manualScopeHosts || [])],
      };
      await storeQuimeraOptions(updated);
      if (
        JSON.stringify(updated.scopeHosts) !==
        JSON.stringify(options.scopeHosts)
      ) {
        await syncQuimeraContentScripts(updated);
      }
      return { success: true, options: updated, pendingHosts: [] };
    }
    const result = await fetchBurpScope(options);
    if (result.status !== 'ok') {
      return { success: false, error: scopeResultError(result) };
    }
    let updated = reconcileBurpScope(
      options,
      result.hosts,
      result.removedHosts
    );
    const hasGlobalAccess = await browserDetector
      .getApi()
      .permissions.contains({ origins: ['<all_urls>'] });
    if (hasGlobalAccess) {
      updated = authorizePendingBurpHosts(
        updated,
        updated.burpScopePendingHosts
      );
    }
    const collectorsChanged =
      JSON.stringify(updated.scopeHosts) !== JSON.stringify(options.scopeHosts);
    await storeQuimeraOptions(updated);
    if (collectorsChanged) await syncQuimeraContentScripts(updated);
    return {
      success: true,
      options: updated,
      pendingHosts: updated.burpScopePendingHosts,
    };
  }

  async function authorizeBurpScopeHosts(requestedHosts) {
    const refreshed = await refreshBurpScope(await getQuimeraOptions());
    if (!refreshed.success) return refreshed;
    const updated = authorizePendingBurpHosts(
      refreshed.options,
      requestedHosts
    );
    await storeQuimeraOptions(updated);
    await syncQuimeraContentScripts(updated);
    return {
      success: true,
      authorizedHosts: updated.burpScopeHosts,
      pendingHosts: updated.burpScopePendingHosts,
    };
  }

  // Do not await startup work before listener registration below: MV3 workers
  // must subscribe synchronously so the event that woke the worker is not lost.
  getQuimeraOptions()
    .then(async initialOptions => {
      await syncQuimeraContentScripts(initialOptions);
      if (!initialOptions.burpScopeSyncEnabled) return;
      browserDetector
        .getApi()
        .alarms.create('quimera-burp-scope-sync', { periodInMinutes: 1 });
      await refreshBurpScope(initialOptions);
    })
    .catch(error =>
      console.error('[Quimera] background initialization failed', error)
    );

  /**
   * Merges the content script's local findings with the browser-cookies
   * ground-truth checks, optionally forwards to the Quimera bridge, and
   * caches the result for the popup.
   * @param {number} tabId
   * @param {object} payload
   * @param {Array<object>} localFindings
   */
  async function ingestQuimeraSnapshot(tabId, payload, localFindings) {
    let cookieFindings = [];
    let cookieReadError = null;
    let rawCookies = [];
    try {
      rawCookies = await browserDetector
        .getApi()
        .cookies.getAll({ url: payload.href });
      cookieFindings = analyzeCookies(rawCookies, payload.jsCookieNames);
    } catch (e) {
      // Not silent: kept on the snapshot so the popup can show it instead of
      // just quietly having fewer cookie-groundtruth findings than expected.
      cookieReadError =
        'Could not read cookies for the HttpOnly cross-check: ' +
        (e?.message || e);
      console.warn('[Quimera] ' + cookieReadError);
    }

    const findings = [...cookieFindings, ...(localFindings || [])];
    quimeraSnapshots[tabId] = {
      payload,
      findings,
      cookieReadError,
      timestamp: Date.now(),
    };
    updateBadge(tabId, findings);

    // Cookie flag findings (Secure/HttpOnly/SameSite/domain) are deliberately NOT sent to the
    // bridge: Quimera-burp already sees those from the Set-Cookie header on proxied HTTP traffic
    // via its own CookieAnalyzer, no need to duplicate that path here. The bridge exists for what
    // Quimera-burp genuinely cannot see any other way, DOM signals and Web Storage, already in
    // `payload` as collected by content.js. cookies/rawCookies above stay local-only, used just for
    // this extension's own standalone Vulns tab.
    //
    // What Quimera-burp's own analysis of this payload finds is deliberately NOT read back or
    // shown anywhere in this extension (used to have its own "Quimera deep analysis" section in
    // the Vulns tab, removed by request): this extension's UI should only ever reflect what IT
    // detected. The send below still happens, that's the whole point of the bridge, Quimera-burp
    // gets the data and surfaces whatever it finds in its own Logger/Issues, that's where it
    // belongs. Only a rejection (bad token, payload too large, malformed JSON, real data loss on
    // Quimera-burp's side) still gets logged, to the console only, for troubleshooting the bridge
    // itself, not as a popup finding.
    const opts = await getQuimeraOptions();
    const bridgePayload = {
      ...payload,
      schemaVersion: 1,
      observedAt: new Date().toISOString(),
      browserCookies:
        opts.collectors?.cookies === false
          ? []
          : rawCookies.map(c => ({
              name: c.name,
              value: c.value,
              domain: c.domain,
              path: c.path,
              secure: Boolean(c.secure),
              httpOnly: Boolean(c.httpOnly),
              sameSite: c.sameSite || '',
            })),
    };
    const bridgeResult = await sendToBridge(opts, bridgePayload, findings);
    quimeraSnapshots[tabId].bridgeStatus = bridgeResult.status;
    if (bridgeResult.status === 'rejected') {
      console.error(
        '[Quimera] bridge rejected snapshot (HTTP ' +
          bridgeResult.httpStatus +
          '): ' +
          bridgeResult.error
      );
    } else if (bridgeResult.status === 'unreachable') {
      console.error(
        '[Quimera] bridge unreachable while sending: ' + payload.href
      );
    } else if (bridgeResult.status === 'ok') {
      console.info('[Quimera] bridge accepted snapshot: ' + payload.href);
    }
    return quimeraSnapshots[tabId];
  }

  // Setting up event listeners synchronously at startup for service worker lifecycle
  browserDetector.getApi().runtime.onConnect.addListener(onConnect);
  browserDetector.getApi().runtime.onMessage.addListener(onRuntimeMessage);
  browserDetector.getApi().runtime.onInstalled.addListener(details => {
    const runtime = browserDetector.getApi().runtime;
    if (details.reason === 'install' && runtime.openOptionsPage) {
      runtime.openOptionsPage();
    }
  });
  browserDetector.getApi().tabs.onUpdated.addListener(onTabsChanged);
  const permissionsApi = browserDetector.getApi().permissions;
  const refreshAfterPermissionChange = () => {
    getQuimeraOptions()
      .then(syncQuimeraContentScripts)
      .catch(error =>
        console.error('[Quimera] permission refresh failed', error)
      );
  };
  permissionsApi?.onAdded?.addListener(refreshAfterPermissionChange);
  permissionsApi?.onRemoved?.addListener(refreshAfterPermissionChange);
  browserDetector.getApi().tabs.onRemoved.addListener(tabId => {
    delete quimeraSnapshots[tabId];
  });
  browserDetector.getApi().alarms.onAlarm.addListener(alarm => {
    if (alarm.name !== 'quimera-burp-scope-sync') return;
    getQuimeraOptions()
      .then(options => refreshBurpScope(options))
      .catch(error =>
        console.error('[Quimera] automatic Burp scope refresh failed', error)
      );
  });

  if (!browserDetector.isSafari()) {
    browserDetector.getApi().cookies.onChanged.addListener(onCookiesChanged);
  }

  if (await isFirefoxAndroid()) {
    const popupOptions = {
      popup: '/interface/popup-mobile/cookie-list.html',
    };
    browserDetector.getApi().action.setPopup(popupOptions);
  }

  if (await isSafariIos()) {
    // If we detect the user is on iOS, mark the browser
    // as Safari in case it was edge or something else.
    browserDetector.overrideBrowserName(Browsers.Safari);
    console.log('Setting up iOS popup');
    const popupOptions = {
      popup: '/interface/popup-mobile/cookie-list.html',
    };
    browserDetector.getApi().action.setPopup(popupOptions);
  }

  if (browserDetector.supportsSidePanel()) {
    browserDetector
      .getApi()
      .sidePanel.setPanelBehavior({ openPanelOnActionClick: false })

      .catch(error => {
        console.error(error);
      });
  }

  /** Firefox reliably consumes a returned Promise, while Chromium MV3 versions are inconsistent
   * about Promise-returning listeners and may resolve sendMessage() with undefined. That lost
   * acknowledgement prevents the content script from marking an accepted snapshot as delivered,
   * so its periodic safety pass sends it again. Use each browser's native async response contract. */
  function returnAsyncResponse(promise, sendResponse) {
    if (browserDetector.isFirefox()) return promise;
    promise.then(sendResponse, error =>
      sendResponse({
        success: false,
        bridgeStatus: 'error',
        error: error?.message || String(error),
      })
    );
    return true;
  }

  function onRuntimeMessage(request, sender, sendResponse) {
    if (request.type === MSG.SET_OPTIONS) {
      return returnAsyncResponse(
        applyQuimeraOptions(request.options).catch(error => ({
          success: false,
          error: error?.message || String(error),
        })),
        sendResponse
      );
    }
    if (request.type === MSG.COLLECTED) {
      const tabId = sender.tab && sender.tab.id;
      if (tabId === undefined) {
        return returnAsyncResponse(
          Promise.resolve({
            success: false,
            bridgeStatus: 'error',
            error: 'Collected snapshot has no sender tab.',
          }),
          sendResponse
        );
      }
      return returnAsyncResponse(
        ingestQuimeraSnapshot(tabId, request.payload, request.findings).then(
          snapshot => ({
            success: true,
            bridgeStatus: snapshot.bridgeStatus,
          }),
          error => {
            console.error('[Quimera] ingest error', error);
            return {
              success: false,
              bridgeStatus: 'error',
              error: error?.message || String(error),
            };
          }
        ),
        sendResponse
      );
    }
    return handleMessage(request, sender, sendResponse);
  }

  /**
   * Handles messages coming from the front end, mostly from the dev tools.
   * Devtools require special handling because not all APIs are available in
   * there, such as tab and permissions.
   * @param {object} request contains the message.
   * @param {MessageSender} sender references the sender of the message, not
   *    used.
   * @param {function} sendResponse callback to respond to the sender.
   * @return {boolean} sometimes
   */
  function handleMessage(request, sender, sendResponse) {
    console.log('message received: ' + (request.type || 'unknown'));
    switch (request.type) {
      case 'getTabs': {
        browserDetector
          .getApi()
          .tabs.query({})
          .then(sendResponse, error => {
            console.error('Failed to get tabs', error);
            sendResponse({
              success: false,
              error: error?.message || String(error),
            });
          });
        return true;
      }
      case 'getCurrentTab': {
        browserDetector
          .getApi()
          .tabs.query({ active: true, currentWindow: true })
          .then(sendResponse, error => {
            console.error('Failed to get current tab', error);
            sendResponse({
              success: false,
              error: error?.message || String(error),
            });
          });
        return true;
      }
      case 'getAllCookies': {
        const getAllCookiesParams = {
          url: request.params.url,
        };
        if (request.params.storeId) {
          getAllCookiesParams.storeId = request.params.storeId;
        }
        browserDetector
          .getApi()
          .cookies.getAll(getAllCookiesParams)
          .then(sendResponse, error => {
            console.error('Failed to get all cookies', error);
            sendResponse({
              success: false,
              error: error?.message || String(error),
            });
          });
        return true;
      }
      case 'saveCookie': {
        browserDetector
          .getApi()
          .cookies.set(request.params.cookie)
          .then(
            cookie => {
              sendResponse({ success: true, cookie });
            },
            error => {
              console.error('Failed to create cookie', error);
              sendResponse({
                success: false,
                error: error?.message || String(error),
              });
            }
          );
        return true;
      }
      case 'removeCookie': {
        const removeParams = {
          name: request.params.name,
          url: request.params.url,
        };
        browserDetector
          .getApi()
          .cookies.remove(removeParams)
          .then(sendResponse, error => {
            console.error('Failed to remove cookie', error);
            sendResponse({
              success: false,
              error: error?.message || String(error),
            });
          });
        return true;
      }
      case 'permissionsContains': {
        permissionHandler
          .checkPermissions(request.params)
          .then(sendResponse, error => {
            console.error('Failed to check permissions', error);
            sendResponse({
              success: false,
              error: error?.message || String(error),
            });
          });
        return true;
      }
      case 'permissionsRequest': {
        permissionHandler
          .requestPermission(request.params)
          .then(sendResponse, error => {
            console.error('Failed to request permission', error);
            sendResponse({
              success: false,
              error: error?.message || String(error),
            });
          });
        return true;
      }
      case 'optionsChanged': {
        sendMessageToAllTabs('optionsChanged', {
          from: request.params.from,
        });
        return true;
      }

      // ------ Quimera additions ------------------------------------------------------------------------------------------------------------------------------------------
      case MSG.GET_SNAPSHOT: {
        // Sent by the popup's Storage/Vulns tabs. Always asks the content
        // script for a fresh snapshot ("muestra la pestaña activa en
        // vivo"); falls back to the last cached one if that fails (e.g.
        // internal browser pages with no content script).
        (async () => {
          const tabId = request.tabId;
          try {
            const fresh = await browserDetector
              .getApi()
              .tabs.sendMessage(tabId, { type: MSG.REQUEST_SNAPSHOT });
            const result = await ingestQuimeraSnapshot(
              tabId,
              fresh.payload,
              fresh.findings
            );
            sendResponse({ success: true, snapshot: result });
          } catch (error) {
            const cached = quimeraSnapshots[tabId];
            sendResponse({
              success: !!cached,
              snapshot: cached || null,
              error: error?.message || String(error),
            });
          }
        })();
        return true;
      }
      case MSG.GET_OPTIONS: {
        getQuimeraOptions().then(sendResponse);
        return true;
      }
      case MSG.PING_BRIDGE: {
        getQuimeraOptions()
          .then(opts => pingBridge(opts))
          .then(result => sendResponse({ connected: !!result, info: result }));
        return true;
      }
      case MSG.CHECK_BRIDGE_AUTH: {
        // Unlike PING_BRIDGE (unauthenticated liveness probe), this hits a token-authenticated
        // endpoint read-only, so "connected" actually means "paired", not just "port is open".
        getQuimeraOptions()
          .then(opts => fetchBurpScope(opts))
          .then(sendResponse);
        return true;
      }
      case MSG.SYNC_BURP_SCOPE: {
        getQuimeraOptions()
          .then(options => refreshBurpScope(options))
          .then(sendResponse, error =>
            sendResponse({
              success: false,
              error: error?.message || String(error),
            })
          );
        return true;
      }
      case MSG.AUTHORIZE_BURP_SCOPE: {
        authorizeBurpScopeHosts(request.hosts).then(sendResponse, error =>
          sendResponse({
            success: false,
            error: error?.message || String(error),
          })
        );
        return true;
      }
    }
  }

  /**
   * Handles connections from clients to this script.
   * @param {Port} port An object which allows two way communication with other
   *    pages.
   */
  function onConnect(port) {
    const extensionListener = function (request, port) {
      console.log('port message received: ' + (request.type || 'unknown'));
      switch (request.type) {
        case 'init_cookieHandler':
          console.log(
            'Devtool cookieHandler connected on tab ' + request.tabId
          );
          connections[request.tabId] = port;
          return;
        case 'init_optionsHandler':
          console.log('optionsHandler connected: ' + port.name);
          connections[port.name] = port;
          return;
      }

      // other message handling.
    };

    // Listen to messages sent from the DevTools page.
    port.onMessage.addListener(extensionListener);

    port.onDisconnect.addListener(function (port) {
      port.onMessage.removeListener(extensionListener);
      const tabs = Object.keys(connections);
      for (let i = 0; i < tabs.length; i++) {
        if (connections[tabs[i]] === port) {
          console.log('script disconnected on tab ' + tabs[i]);
          delete connections[tabs[i]];
          break;
        }
      }
    });
  }

  /**
   * Sends a message to a script running in a specific tab.
   * @param {number} tabId Id of the tab to send the message to.
   * @param {string} type Type of message, used by the client to parse the data.
   * @param {any} data Data to send to the client.
   */
  function sendMessageToTab(tabId, type, data) {
    if (tabId in connections) {
      connections[tabId].postMessage({
        type: type,
        data: data,
      });
    }
  }

  /**
   * Sends a message to all the tabs connected.
   * @param {string} type Type of message, used by the client to parse the data.
   * @param {any} data Data to send to the client.
   */
  function sendMessageToAllTabs(type, data) {
    const tabs = Object.keys(connections);
    for (let i = 0; i < tabs.length; i++) {
      sendMessageToTab(tabs[i], type, data);
    }
  }

  /**
   * Handles events that is triggered when a cookie changes.
   * @param {object} changeInfo An object containing details of the change that
   *     occurred.
   */
  function onCookiesChanged(changeInfo) {
    console.log('cookies changed, notifying all devtools');
    sendMessageToAllTabs('cookiesChanged', changeInfo);
  }

  /**
   * Handles the event that is fired when a tab is updated.
   * @param {number} tabId The id of the tab that changed.
   * @param {object} changeInfo Properties of the tab that changed.
   * @param {object} _tab The new state of the tab.
   */
  function onTabsChanged(tabId, changeInfo, _tab) {
    console.log('tabs changed', tabId, changeInfo, _tab);
    sendMessageToTab(tabId, 'tabsChanged', changeInfo);
    if (changeInfo.status === 'loading') {
      // Navigating away: clear the stale badge count from whatever page was
      // here before, content.js's own passive capture will set a fresh one
      // once the new page settles (see collectAndSend's setTimeout).
      browserDetector.getApi().action.setBadgeText({ tabId, text: '' });
    }
  }

  /**
   * Special function to detect if we are running on Firefox for Android.
   * @return {Promise<boolean>} Responds true if it is Firefox on android,
   *     otherwise false.
   */
  async function isFirefoxAndroid() {
    if (!browserDetector.isFirefox()) {
      return false;
    }

    try {
      const info = await browserDetector.getApi().runtime.getPlatformInfo();
      return info.os === 'android';
    } catch (e) {
      console.error(e);
      return false;
    }
  }

  /**
   * Special function to detect if we are running on Safari on iOS.
   *
   * Any browser running on iOS would be considered Safari since they
   * all are wrappers.
   *
   * @return {Promise<boolean>} Responds true if it is Safari on iOS,
   *     otherwise false.
   */
  async function isSafariIos() {
    try {
      const info = await browserDetector.getApi().runtime.getPlatformInfo();
      console.log('check for safari on ios: ', info.os);
      return info.os === 'ios';
    } catch (e) {
      console.error(e);
      return false;
    }
  }
})();
