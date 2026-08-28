import { Animate } from '../lib/animate.js';
import { BrowserDetector } from '../lib/browserDetector.js';
import { MSG, SEVERITY_ORDER } from '../lib/quimera/constants.js';

/**
 * Wires the Cookies | Storage | Vulns tab strip added on top of
 * Cookie-Editor's popup. Kept as its own module, loaded after
 * cookie-list.js, so it never has to touch that file's internals: it only
 * shows/hides the existing #cookie-container and two new sibling panels.
 */
(async function () {
  const browserDetector = new BrowserDetector();

  const tabButtons = {
    cookies: document.getElementById('quimera-tab-cookies'),
    storage: document.getElementById('quimera-tab-storage'),
    vulns: document.getElementById('quimera-tab-vulns'),
  };
  const panels = {
    cookies: document.getElementById('cookie-container'),
    storage: document.getElementById('quimera-storage-container'),
    vulns: document.getElementById('quimera-vulns-container'),
  };
  const buttonBars = document.querySelectorAll('.button-bar');

  for (const [name, button] of Object.entries(tabButtons)) {
    button.addEventListener('click', () => activate(name));
  }

  /** @param {string} name one of 'cookies' | 'storage' | 'vulns'. */
  async function activate(name) {
    for (const [key, button] of Object.entries(tabButtons)) {
      const isActive = key === name;
      button.classList.toggle('active', isActive);
      button.setAttribute('aria-selected', String(isActive));
      panels[key].classList.toggle('hidden', !isActive);
    }
    // The cookie action bar (Add/Delete/Import/Export) only makes sense on
    // the Cookies tab.
    buttonBars.forEach(bar => {
      bar.style.display = name === 'cookies' ? '' : 'none';
    });

    if (name === 'storage') await renderStorage();
    if (name === 'vulns') await renderVulns();
  }

  /** @return {Promise<{tabId:number, url:string}|null>} */
  async function getCurrentTab() {
    const [tab] = await browserDetector
      .getApi()
      .tabs.query({ active: true, currentWindow: true });
    return tab ? { tabId: tab.id, url: tab.url } : null;
  }

  /** @return {Promise<{success:boolean, snapshot:object|null, error?:string}>} */
  async function requestSnapshot() {
    const tab = await getCurrentTab();
    if (!tab) return { success: false, snapshot: null };
    return browserDetector.getApi().runtime.sendMessage({
      type: MSG.GET_SNAPSHOT,
      tabId: tab.tabId,
    });
  }

  async function renderStorage() {
    panels.storage.textContent = '';
    const tab = await getCurrentTab();
    const result = await requestSnapshot();
    if (!result.success || !result.snapshot || !tab) {
      panels.storage.appendChild(
        emptyState(
          "Couldn't read this page (internal browser page, or it hasn't finished loading yet)."
        )
      );
      return;
    }

    const { payload } = result.snapshot;
    const section = document.createElement('div');
    section.className = 'quimera-storage';

    section.appendChild(
      storageGroup('localStorage', payload.localStorage, tab.tabId)
    );
    section.appendChild(
      storageGroup('sessionStorage', payload.sessionStorage, tab.tabId)
    );

    if (payload.jsCookieNames && payload.jsCookieNames.length) {
      const group = document.createElement('div');
      group.className = 'quimera-storage-group';
      const heading = document.createElement('h3');
      heading.textContent =
        'document.cookie (JS-readable, ' + payload.jsCookieNames.length + ')';
      group.appendChild(heading);
      const list = document.createElement('div');
      list.textContent = payload.jsCookieNames.join(', ');
      group.appendChild(list);
      section.appendChild(group);
    }

    panels.storage.appendChild(section);
  }

  /**
   * localStorage/sessionStorage group: same create/edit/delete workflow as
   * the Cookies tab, backed by chrome.scripting.executeScript running
   * setItem()/removeItem() directly on the page (requires the "scripting"
   * permission, already declared in every manifest).
   * @param {string} storageType 'localStorage' or 'sessionStorage'.
   * @param {object} dump key/value map.
   * @param {number} tabId
   * @return {Element}
   */
  function storageGroup(storageType, dump, tabId) {
    const group = document.createElement('div');
    group.className = 'quimera-storage-group';
    const entries = Object.entries(dump || {});

    const headingRow = document.createElement('div');
    headingRow.className = 'quimera-storage-group-heading';
    const heading = document.createElement('h3');
    heading.textContent = storageType + ' (' + entries.length + ')';
    headingRow.appendChild(heading);

    const list = document.createElement('div');
    list.className = 'quimera-storage-list';

    const addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.className = 'quimera-storage-add';
    addBtn.textContent = '+ Add';
    addBtn.addEventListener('click', () => {
      const emptyEl = list.querySelector('.quimera-empty');
      if (emptyEl) emptyEl.remove();
      const row = buildStorageRow(storageType, tabId, '', '', true);
      list.insertBefore(row, list.firstChild);
      // Freshly-added row starts already expanded, no slide-open animation
      // needed for something that didn't exist a moment ago, just show it.
      const expando = row.querySelector('.expando');
      expando.style.display = 'flex';
      expando.style.maxHeight = 'none';
      expando.style.overflow = 'visible'; // let the value textarea's resize handle work right away
      row.querySelector('.quimera-kv-header').classList.add('active');
      row
        .querySelector('.quimera-kv-header')
        .setAttribute('aria-expanded', 'true');
      row.querySelector('.quimera-kv-key-input').focus();
    });
    headingRow.appendChild(addBtn);
    group.appendChild(headingRow);
    group.appendChild(list);

    if (entries.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'quimera-empty';
      empty.textContent = 'Empty';
      list.appendChild(empty);
      return group;
    }

    for (const [key, value] of entries) {
      list.appendChild(buildStorageRow(storageType, tabId, key, value, false));
    }
    return group;
  }

  /**
   * One localStorage/sessionStorage entry, built as the same expand-in-place
   * accordion the Cookies tab uses (click the header row to slide open a
   * form with Save/Delete icon buttons, click again to collapse), rather
   * than a separate edit block replacing the row. Same interaction the rest
   * of the popup already trains you on.
   * @param {string} storageType
   * @param {number} tabId
   * @param {string} key existing key, or '' for a brand-new "+ Add" row.
   * @param {string} value existing value, or '' for a brand-new row.
   * @param {boolean} isNew true for the "+ Add" row (no Delete button, key editable).
   * @return {Element}
   */
  function buildStorageRow(storageType, tabId, key, value, isNew) {
    const row = document.createElement('div');
    row.className = 'quimera-kv-row';

    // ── Header: collapsed summary, click to expand/collapse. Reuses
    // cookie-editor's own `container` class (padding: 8px 12px) verbatim,
    // same box model as a cookie row's header. ─────────────────────────
    const header = document.createElement('div');
    header.className = 'quimera-kv-header container';
    header.tabIndex = 0;
    header.setAttribute('role', 'button');
    header.setAttribute('aria-expanded', 'false');
    header.appendChild(svgIcon('angle-down', 'icon arrow'));

    const headerName = document.createElement('span');
    headerName.className = 'quimera-kv-header-name';
    headerName.textContent = key || '(new entry)';
    header.appendChild(headerName);

    const headerExtra = document.createElement('span');
    headerExtra.className = 'quimera-kv-header-extra';
    headerExtra.textContent = truncateForDisplay(value);
    header.appendChild(headerExtra);

    if (!isNew) {
      // `btns`/`delete` are cookie-editor's own literal, unprefixed class
      // names (see .btns button.delete in style.css), reused as-is so the
      // floating delete button is pixel-identical to a cookie row's,
      // instead of a hand-approximated lookalike.
      const btns = document.createElement('div');
      btns.className = 'btns';
      btns.appendChild(
        spriteIconButton('trash', 'Delete', 'delete', () => onDelete())
      );
      header.appendChild(btns);
    }

    header.addEventListener('click', async e => {
      if (e.target.closest('.btns')) return; // let the delete icon handle its own click
      const isActive = header.classList.toggle('active');
      header.setAttribute('aria-expanded', String(isActive));
      if (!isActive) {
        // Closing: re-clip in case it was released below while open, so the
        // slide-shut animation doesn't show the textarea poking out of it.
        expando.style.overflow = 'hidden';
      }
      if (isActive && !isNew) {
        // The snapshot's value may have been capped for the vuln-engine/
        // bridge payload (see MAX_STORAGE_VALUE_LEN in content.js), fine
        // for analysis, NOT fine for editing: a truncated value would show
        // as broken JSON here, and worse, silently overwrite the real
        // entry with a cut-off copy if saved without noticing. Always
        // re-read the real, complete, live value straight from the page
        // before letting anyone edit or save it.
        try {
          const fresh = await readStorageItem(tabId, storageType, key);
          if (fresh !== null && fresh !== undefined) {
            valueInput.value = fresh;
            const pretty = tryFormatJson(fresh);
            if (pretty !== null) {
              valueInput.value = pretty;
              valueInput.classList.add('json');
            } else {
              valueInput.classList.remove('json');
            }
          }
        } catch (err) {
          showInlineError(
            wrapper,
            'Could not re-read the live value: ' + errorMessage(err)
          );
        }
      }
      Animate.toggleSlide(expando, () => {
        if (isActive) {
          // Fully open: release the fixed height the slide animation froze
          // it at, otherwise dragging the value textarea's resize handle
          // (useful for big JSON blobs) grows it invisibly behind this
          // container's own clipped max-height instead of actually
          // becoming visible. The next close click re-measures the real
          // (possibly now taller) content height fresh, see Animate
          // .toggleSlide's own data-max-height handling.
          expando.style.maxHeight = 'none';
          expando.style.overflow = 'visible';
        }
      });
    });
    header.addEventListener('keydown', e => {
      if (e.code === 'Space' || e.code === 'Enter') {
        e.preventDefault();
        header.click();
      }
    });
    row.appendChild(header);

    // ── Expando: the actual edit form, hidden until the header is
    // clicked. `expando`/`wrapper`/`action-btns`/`form`/`container` are
    // all cookie-editor's own literal class names, reused as-is (see
    // style.css: .expando .container.form, .action-btns, .action-btns
    // button.save/.delete) so the whole form is styled by the SAME rules
    // a cookie's edit form is, not a re-approximated copy of them. ──────
    const expando = document.createElement('div');
    expando.className = 'expando';
    expando.setAttribute('aria-hidden', 'true');

    const wrapper = document.createElement('div');
    wrapper.className = 'wrapper';

    const actionBtns = document.createElement('div');
    actionBtns.className = 'action-btns';
    actionBtns.appendChild(
      spriteIconButton('save', 'Save', 'save', () => onSave())
    );
    if (!isNew) {
      actionBtns.appendChild(
        spriteIconButton('trash', 'Delete', 'delete', () => onDelete())
      );
    }
    wrapper.appendChild(actionBtns);

    const form = document.createElement('div');
    form.className = 'form container';

    const keyLabel = document.createElement('label');
    keyLabel.textContent = 'Key';
    form.appendChild(keyLabel);
    const keyInput = document.createElement('input');
    keyInput.type = 'text';
    keyInput.className = 'quimera-kv-key-input';
    keyInput.value = key;
    // Renaming an existing key isn't supported inline (ambiguous: rename, or
    // a new key with the old one left behind?). To rename, delete the old
    // entry and use "+ Add" for the new name, same two-step flow a real
    // localStorage rename always is anyway.
    keyInput.readOnly = !isNew;
    form.appendChild(keyInput);

    const valueLabelRow = document.createElement('div');
    valueLabelRow.className = 'quimera-kv-value-label-row';
    const valueLabel = document.createElement('label');
    valueLabel.textContent = 'Value';
    valueLabelRow.appendChild(valueLabel);
    const formatBtn = document.createElement('button');
    formatBtn.type = 'button';
    formatBtn.className = 'quimera-kv-format-btn';
    formatBtn.textContent = 'Format JSON';
    valueLabelRow.appendChild(formatBtn);
    form.appendChild(valueLabelRow);

    const valueInput = document.createElement('textarea');
    valueInput.className = 'quimera-kv-value-input';
    valueInput.value = value == null ? '' : value;

    // Pretty-print on open if the stored value happens to be JSON (very
    // common for Web Storage, apps almost always store it minified), a
    // monospace, indented view is far more readable/editable than a single
    // packed line. Saving writes back exactly what's in the box, edits and
    // all, no attempt to re-minify.
    const prettyOnOpen = tryFormatJson(valueInput.value);
    if (prettyOnOpen !== null) {
      valueInput.value = prettyOnOpen;
      valueInput.classList.add('json');
    }

    formatBtn.addEventListener('click', e => {
      e.stopPropagation();
      const pretty = tryFormatJson(valueInput.value);
      if (pretty === null) {
        showInlineError(wrapper, 'Not valid JSON.');
        return;
      }
      valueInput.value = pretty;
      valueInput.classList.add('json');
      clearInlineError(wrapper);
    });

    form.appendChild(valueInput);

    wrapper.appendChild(form);
    expando.appendChild(wrapper);
    row.appendChild(expando);

    /** @param {string} spriteId @param {string} cls @return {SVGElement} */
    function svgIcon(spriteId, cls) {
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('class', cls);
      const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
      use.setAttribute('href', '../sprites/solid.svg#' + spriteId);
      svg.appendChild(use);
      return svg;
    }

    /**
     * @param {string} spriteId
     * @param {string} label
     * @param {string} variant 'save' or 'delete', cookie-editor's own literal
     *     class names, this is what the global hover-tint rules key off.
     * @param {function} onClick
     * @return {Element}
     */
    function spriteIconButton(spriteId, label, variant, onClick) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = variant;
      btn.title = label;
      btn.setAttribute('aria-label', label);
      btn.appendChild(svgIcon(spriteId, 'icon'));
      btn.addEventListener('click', e => {
        e.stopPropagation();
        onClick();
      });
      return btn;
    }

    async function onSave() {
      const newKey = keyInput.value.trim();
      if (!newKey) {
        showInlineError(wrapper, 'Key cannot be empty.');
        return;
      }
      try {
        await writeStorageItem(tabId, storageType, newKey, valueInput.value);
        await renderStorage();
      } catch (err) {
        showInlineError(wrapper, 'Failed to save: ' + errorMessage(err));
      }
    }

    async function onDelete() {
      try {
        await removeStorageItem(tabId, storageType, key);
        await renderStorage();
      } catch (err) {
        showInlineError(wrapper, 'Failed to delete: ' + errorMessage(err));
      }
    }

    return row;
  }

  /**
   * Reads the REAL, complete, live value straight from the page, bypassing
   * whatever length cap the passive snapshot collector applied (see
   * MAX_STORAGE_VALUE_LEN in content.js), which exists for the vuln-engine
   * and bridge payload's sake, not for editing.
   * @param {number} tabId
   * @param {string} storageType
   * @param {string} key
   * @return {Promise<string|null>}
   */
  async function readStorageItem(tabId, storageType, key) {
    const results = await browserDetector.getApi().scripting.executeScript({
      target: { tabId },
      func: (type, k) => window[type].getItem(k),
      args: [storageType, key],
    });
    return results && results[0] ? results[0].result : null;
  }

  /**
   * @param {number} tabId
   * @param {string} storageType
   * @param {string} key
   * @param {string} value
   */
  async function writeStorageItem(tabId, storageType, key, value) {
    await browserDetector.getApi().scripting.executeScript({
      target: { tabId },
      func: (type, k, v) => {
        window[type].setItem(k, v);
      },
      args: [storageType, key, value],
    });
  }

  /**
   * @param {number} tabId
   * @param {string} storageType
   * @param {string} key
   */
  async function removeStorageItem(tabId, storageType, key) {
    await browserDetector.getApi().scripting.executeScript({
      target: { tabId },
      func: (type, k) => {
        window[type].removeItem(k);
      },
      args: [storageType, key],
    });
  }

  /** @param {Element} container @param {string} message */
  function showInlineError(container, message) {
    let err = container.querySelector('.quimera-kv-edit-error');
    if (!err) {
      err = document.createElement('div');
      err.className = 'quimera-kv-edit-error';
      container.appendChild(err);
    }
    err.textContent = message;
  }

  /** @param {Element} container */
  function clearInlineError(container) {
    const err = container.querySelector('.quimera-kv-edit-error');
    if (err) err.remove();
  }

  /** @param {any} err @return {string} */
  function errorMessage(err) {
    return (err && err.message) || String(err);
  }

  /**
   * @param {string} text
   * @return {string|null} the pretty-printed (2-space indented) form if
   *     `text` parses as JSON, otherwise null. Objects/arrays only, not
   *     bare JSON primitives ("42", "true", a quoted string), those are
   *     technically valid JSON but formatting them teaches nothing and
   *     would just quietly wrap a bare number in quotes-vs-not confusion.
   */
  function tryFormatJson(text) {
    if (typeof text !== 'string') return null;
    const trimmed = text.trim();
    if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return null;
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch (e) {
      return null;
    }
  }

  async function renderVulns() {
    panels.vulns.textContent = '';
    const result = await requestSnapshot();
    if (!result.success || !result.snapshot) {
      panels.vulns.appendChild(
        emptyState(
          "Couldn't read this page (internal browser page, or it hasn't finished loading yet)."
        )
      );
      return;
    }

    const { findings, cookieReadError } = result.snapshot;

    // A partial-collection warning: something that quietly shrinks the
    // findings count if left unsurfaced (missing the HttpOnly cross-check
    // for this page).
    if (cookieReadError) {
      panels.vulns.appendChild(warningBanner(cookieReadError));
    }

    // Deliberately local-only: this extension's own findings, nothing from the (optional) bridge
    // to Quimera-burp. Quimera-burp still receives every snapshot if the bridge is on (see
    // ingestQuimeraSnapshot in cookie-editor.js), whatever ITS analysis finds belongs in its own
    // Logger/Issues, not mirrored back into this popup, by request, this UI should only ever show
    // what the extension itself detected.
    const localSection = document.createElement('div');
    localSection.className = 'quimera-vulns-section';
    const localHeading = document.createElement('h3');
    localHeading.textContent =
      'Findings (' + (findings ? findings.length : 0) + ')';
    localSection.appendChild(localHeading);
    localSection.appendChild(findingsList(findings));
    panels.vulns.appendChild(localSection);
  }

  /** @param {string} message @return {Element} */
  function warningBanner(message) {
    const el = document.createElement('div');
    el.className = 'quimera-warning-banner';
    el.textContent = '⚠ ' + message;
    return el;
  }

  /** @param {Array<object>} findings @return {Element} */
  function findingsList(findings) {
    const list = document.createElement('div');
    if (!findings || findings.length === 0) {
      list.appendChild(emptyState('No findings on this page.'));
      return list;
    }
    const sorted = [...findings].sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    );
    for (const f of sorted) {
      const item = document.createElement('div');
      item.className =
        'quimera-finding quimera-sev-' +
        (f.severity || 'INFORMATION').toLowerCase();

      const title = document.createElement('div');
      title.className = 'quimera-finding-title';
      const badge = document.createElement('span');
      badge.className = 'quimera-badge';
      badge.textContent = f.severity || 'INFO';
      title.appendChild(badge);
      title.appendChild(document.createTextNode(' ' + f.title));
      item.appendChild(title);

      if (f.description) {
        const desc = document.createElement('div');
        desc.className = 'quimera-finding-desc';
        desc.textContent = f.description;
        item.appendChild(desc);
      }
      if (f.evidence) {
        const evidence = document.createElement('div');
        evidence.className = 'quimera-finding-evidence';
        evidence.textContent = truncateForDisplay(f.evidence);
        item.appendChild(evidence);
      }
      list.appendChild(item);
    }
    return list;
  }

  /** @param {string} text @return {Element} */
  function emptyState(text) {
    const el = document.createElement('div');
    el.className = 'quimera-empty';
    el.textContent = text;
    return el;
  }

  /** @param {string} value @return {string} */
  function truncateForDisplay(value) {
    if (typeof value !== 'string') return String(value);
    return value.length > 300 ? value.slice(0, 300) + '…' : value;
  }

  // ── Bridge widget: fast enable/port/status access right in the popup header,
  // no trip to Options needed for the two settings people touch daily. ──────
  initBridgeWidget();

  /** Wires the small "● 8199" button in the header and its dropdown. */
  async function initBridgeWidget() {
    const toggleBtn = document.getElementById('quimera-bridge-toggle');
    const dot = document.getElementById('quimera-bridge-dot');
    const portLabel = document.getElementById('quimera-bridge-port-label');
    const popover = document.getElementById('quimera-bridge-popover');
    const enabledInput = document.getElementById(
      'quimera-bridge-widget-enabled'
    );
    const portInput = document.getElementById('quimera-bridge-widget-port');
    const statusEl = document.getElementById('quimera-bridge-widget-status');
    const saveBtn = document.getElementById('quimera-bridge-widget-save');
    const moreLink = document.getElementById('quimera-bridge-widget-more');

    if (!toggleBtn) return; // defensive: markup missing for some reason, never crash the popup

    await refreshWidget();

    toggleBtn.addEventListener('click', () => {
      popover.classList.toggle('hidden');
    });
    document.addEventListener('click', e => {
      if (
        !popover.classList.contains('hidden') &&
        !popover.contains(e.target) &&
        e.target !== toggleBtn &&
        !toggleBtn.contains(e.target)
      ) {
        popover.classList.add('hidden');
      }
    });
    moreLink.addEventListener('click', e => {
      e.preventDefault();
      openFullOptionsPage();
    });
    saveBtn.addEventListener('click', async () => {
      saveBtn.disabled = true;
      statusEl.textContent = 'Saving…';
      try {
        // Merge into the FULL saved options object, this widget only edits two
        // fields, the rest (scope, token, per-collector toggles) live in
        // Options and must survive untouched.
        const current = (await sendMessage(MSG.GET_OPTIONS)) || {};
        const updated = {
          ...current,
          bridgeEnabled: enabledInput.checked,
          bridgePort:
            parseInt(portInput.value, 10) || current.bridgePort || 8199,
        };
        await sendMessage(MSG.SET_OPTIONS, { options: updated });
      } finally {
        saveBtn.disabled = false;
        await refreshWidget();
      }
    });

    async function refreshWidget() {
      const opts = await sendMessage(MSG.GET_OPTIONS);
      if (opts) {
        enabledInput.checked = !!opts.bridgeEnabled;
        portInput.value = opts.bridgePort || 8199;
        portLabel.textContent = String(opts.bridgePort || 8199);
      }
      if (!opts || !opts.bridgeEnabled) {
        dot.textContent = '○';
        dot.style.color = '';
        statusEl.textContent = 'Bridge disabled.';
        return;
      }
      statusEl.textContent = 'Checking…';
      const ping = await sendMessage(MSG.PING_BRIDGE);
      const connected = !!(ping && ping.connected);
      dot.textContent = connected ? '●' : '●';
      dot.style.color = connected ? '#1e824c' : '#cf000f';
      statusEl.textContent = connected
        ? 'Connected to Quimera.'
        : 'Not connected. Is Quimera running in Burp on this port?';
    }

    function openFullOptionsPage() {
      if (browserDetector.getApi().runtime.openOptionsPage) {
        browserDetector.getApi().runtime.openOptionsPage();
      } else {
        window.open(
          browserDetector
            .getApi()
            .runtime.getURL('interface/options/options.html')
        );
      }
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
})();
