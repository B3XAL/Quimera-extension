/**
 * Talks to the loopback bridge server embedded in the Quimera Burp
 * extension (com.b3xal.headeranalyzer.browser.BrowserBridgeServer).
 * Runs only from the background service worker (chrome-extension:// origin)
 * so an https page never has to make a mixed-content / Private Network
 * Access call to 127.0.0.1 itself, see plan Part A.
 */

const FETCH_TIMEOUT_MS = 4000;

function bridgeUrl(opts, path) {
  return 'http://127.0.0.1:' + (opts.bridgePort || 8199) + path;
}

function withTimeout(promise, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { controller, timer, promise };
}

/**
 * @param {object} opts QuimeraOptions.
 * @return {Promise<object|null>} the ping response, or null if unreachable.
 */
export async function pingBridge(opts) {
  const { controller, timer } = withTimeout(null, FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(bridgeUrl(opts, '/quimera/v1/ping'), {
      method: 'GET',
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    clearTimeout(timer);
    return null;
  }
}

/** Fetches the bounded host snapshot currently observed in Burp's Target Scope. */
export async function fetchBurpScope(opts) {
  if (!opts.bridgeEnabled) return { status: 'disabled', hosts: [] };
  if (!opts.bridgeTokenEnabled || !opts.bridgeToken) {
    return {
      status: 'rejected',
      httpStatus: 0,
      error: 'A bridge token is required',
    };
  }
  const { controller, timer } = withTimeout(null, FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(bridgeUrl(opts, '/quimera/v1/scope'), {
      method: 'GET',
      headers: { 'X-Quimera-Token': opts.bridgeToken },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      let error = `HTTP ${res.status}`;
      try {
        error = (await res.json()).error || error;
      } catch (e) {
        // Keep the HTTP status for a non-JSON response.
      }
      return { status: 'rejected', httpStatus: res.status, error };
    }
    const data = await res.json();
    if (
      data.schemaVersion !== 1 ||
      !Array.isArray(data.hosts) ||
      !Array.isArray(data.removedHosts)
    ) {
      return {
        status: 'rejected',
        httpStatus: 200,
        error: 'Invalid scope response',
      };
    }
    return {
      status: 'ok',
      hosts: data.hosts,
      removedHosts: data.removedHosts,
    };
  } catch (e) {
    clearTimeout(timer);
    return { status: 'unreachable', hosts: [] };
  }
}

/**
 * Sends a collected payload + locally-computed findings to Quimera for deep
 * analysis. Distinguishes two very different situations instead of
 * collapsing both to null like the previous version did:
 *   - 'unreachable': nothing is listening on that port. Expected and quiet,
 *     Quimera simply isn't running right now, the extension must keep
 *     working standalone either way.
 *   - 'rejected': something DID answer, but said no (bad token, malformed
 *     payload, disabled, body too large, ...). This means real data was
 *     collected and then discarded, it must be visible, not swallowed, so
 *     the caller can show it instead of just quietly showing "0 findings".
 * @param {object} opts QuimeraOptions.
 * @param {object} payload the collected snapshot from content.js.
 * @param {Array<object>} localFindings findings from the local engine.
 * @return {Promise<{status: 'ok', findings: Array<object>} |
 *                   {status: 'unreachable'} |
 *                   {status: 'disabled'} |
 *                   {status: 'rejected', httpStatus: number, error: string}>}
 */
export async function sendToBridge(opts, payload, localFindings) {
  if (!opts.bridgeEnabled) return { status: 'disabled' };
  const { controller, timer } = withTimeout(null, FETCH_TIMEOUT_MS);
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (!opts.bridgeTokenEnabled || !opts.bridgeToken) {
      return {
        status: 'rejected',
        httpStatus: 0,
        error: 'A bridge token is required',
      };
    }
    headers['X-Quimera-Token'] = opts.bridgeToken;
    const res = await fetch(bridgeUrl(opts, '/quimera/v1/ingest'), {
      method: 'POST',
      headers,
      body: JSON.stringify({ payload, localFindings }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      let error = 'HTTP ' + res.status;
      try {
        const errBody = await res.json();
        if (errBody && errBody.error) error = errBody.error;
      } catch (e) {
        /* non-JSON error body, keep the generic "HTTP <status>" message */
      }
      return { status: 'rejected', httpStatus: res.status, error };
    }
    const data = await res.json();
    return { status: 'ok', findings: data.findings || [] };
  } catch (e) {
    clearTimeout(timer);
    // fetch() throws for connection-refused/timeout/DNS failure, all mean
    // "nothing reachable there", the expected/quiet case, not a rejection.
    return { status: 'unreachable' };
  }
}
