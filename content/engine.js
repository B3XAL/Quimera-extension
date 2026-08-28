/**
 * Quimera's own client-side vulnerability detection engine. Plain classic
 * script (no import/export) so it can be loaded directly as a content
 * script alongside content.js and inject-mainworld.js, sharing the same
 * isolated-world global scope, no bundler needed.
 *
 * This is what makes the extension useful WITHOUT Burp/Quimera running:
 * everything here is pure data-in/findings-out, computed entirely in the
 * browser from what content.js and inject-mainworld.js collected.
 *
 * A finding is: { title, severity, confidence, evidence, description,
 * category }. severity/confidence mirror Quimera's own vocabulary
 * (HIGH/MEDIUM/LOW/INFORMATION, CERTAIN/FIRM/TENTATIVE) so the two tools
 * read the same way side by side.
 */
(function (global) {
  'use strict';

  const SENSITIVE_KEY_KEYWORDS = [
    'token',
    'jwt',
    'session',
    'sessid',
    'auth',
    'sso',
    'secret',
    'password',
    'passwd',
    'credential',
    'apikey',
    'api_key',
    'accesstoken',
    'refreshtoken',
    'idtoken',
  ];

  // Keys that are public-by-design, so a match there should never read as a
  // leaked secret (Quimera's own exploitability bar).
  const PUBLIC_KEY_PATTERNS = [
    /^AIza[0-9A-Za-z\-_]{35}$/, // Google/Firebase browser API key
  ];

  const MAX_VALUE_LEN = 2048;

  /** @return {boolean} true if the string looks like a base64url JWT. */
  function looksLikeJwt(value) {
    if (typeof value !== 'string') return false;
    const parts = value.split('.');
    if (parts.length !== 3) return false;
    const header = decodeJwtPart(parts[0]);
    if (!header) return false;
    try {
      const json = JSON.parse(header);
      return typeof json === 'object' && json !== null && 'alg' in json;
    } catch (e) {
      return false;
    }
  }

  /** Decodes one base64url JWT segment, returns null if it fails. */
  function decodeJwtPart(part) {
    try {
      let b64 = part.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      return atob(b64);
    } catch (e) {
      return null;
    }
  }

  /** Decodes a JWT into {header, payload} objects, or null if malformed. */
  function decodeJwt(value) {
    const parts = value.split('.');
    if (parts.length !== 3) return null;
    try {
      return {
        header: JSON.parse(decodeJwtPart(parts[0])),
        payload: JSON.parse(decodeJwtPart(parts[1])),
      };
    } catch (e) {
      return null;
    }
  }

  /** JWT-specific findings: alg:none, missing exp, expired, long-lived. dedupeKey lets
   * {@link mergeDuplicateFindings} collapse the SAME token found at several locations (very
   * common with OIDC libraries that store the raw access/id token under more than one storage
   * key, e.g. angular-auth-oidc-client's authnResult.access_token and authzData holding the
   * identical string) into one finding instead of reporting it once per location. Scoped per
   * check type (jwt-found/jwt-alg-none/...), never across different checks, so only genuine
   * repeats of the exact same check on the exact same token ever merge. */
  function analyzeJwt(value, whereLabel) {
    const findings = [];
    const decoded = decodeJwt(value);
    if (!decoded) return findings;
    const { header, payload } = decoded;

    findings.push(
      mk(
        'JWT found: ' + whereLabel,
        'INFORMATION',
        'CERTAIN',
        'browser-auth',
        truncate(value),
        'A JSON Web Token was found in ' +
          whereLabel +
          '. Claims present: ' +
          Object.keys(payload || {}).join(', ') +
          '.',
        {
          key: 'jwt-found:' + value,
          location: whereLabel,
          baseTitle: 'JWT found',
        }
      )
    );

    if (header && (header.alg === 'none' || header.alg === 'None')) {
      findings.push(
        mk(
          'JWT accepts alg:none: ' + whereLabel,
          'HIGH',
          'CERTAIN',
          'browser-auth',
          JSON.stringify(header),
          "This JWT's header declares alg:none. If the server actually honors " +
            'that algorithm, the signature can be stripped entirely and the ' +
            'token forged with arbitrary claims. Verify server-side handling ' +
            'with a modified copy of this token before reporting as exploitable.',
          {
            key: 'jwt-alg-none:' + value,
            location: whereLabel,
            baseTitle: 'JWT accepts alg:none',
          }
        )
      );
    }
    if (!payload || payload.exp === undefined) {
      findings.push(
        mk(
          'JWT has no expiry (exp) claim: ' + whereLabel,
          'HIGH',
          'CERTAIN',
          'browser-auth',
          JSON.stringify(payload || {}),
          'This JWT has no "exp" claim, so it never expires by its own contents. ' +
            'If the server does not enforce a separate expiry, a captured token ' +
            'remains valid indefinitely.',
          {
            key: 'jwt-no-exp:' + value,
            location: whereLabel,
            baseTitle: 'JWT has no expiry (exp) claim',
          }
        )
      );
    } else {
      const now = Date.now() / 1000;
      if (payload.exp < now) {
        findings.push(
          mk(
            'Expired JWT observed: ' + whereLabel,
            'INFORMATION',
            'CERTAIN',
            'browser-auth',
            'exp=' + payload.exp,
            "This JWT's exp claim is in the past. Informational only, capture " +
              'a live token to test with.',
            {
              key: 'jwt-expired:' + value,
              location: whereLabel,
              baseTitle: 'Expired JWT observed',
            }
          )
        );
      }
    }
    return findings;
  }

  /** A literal value worth flagging as an opaque (non-JWT) token. */
  function looksLikeOpaqueToken(value) {
    const v = (value || '').trim();
    if (v.length < 12 || v.length > MAX_VALUE_LEN) return false;
    if (/\s/.test(v)) return false;
    const lower = v.toLowerCase();
    if (
      [
        'null',
        'undefined',
        'false',
        'true',
        'none',
        'guest',
        'anonymous',
      ].includes(lower)
    )
      return false;
    // A leading '/' is a URL/route path (e.g. "/Account/ResetPassword" from
    // a global like `url_ResetPassword`), not a secret, even though '/' is
    // also a valid base64 character and would otherwise pass the charset
    // check below. Real tokens don't start with a literal path separator.
    if (v.startsWith('/')) return false;
    return /^[A-Za-z0-9+/=_.~-]+$/.test(v);
  }

  function isSensitiveKeyName(key) {
    const lower = (key || '').toLowerCase();
    return SENSITIVE_KEY_KEYWORDS.some(kw => lower.includes(kw));
  }

  function isPublicByDesign(value) {
    return PUBLIC_KEY_PATTERNS.some(re => re.test(value));
  }

  function truncate(value) {
    if (typeof value !== 'string') return value;
    return value.length > MAX_VALUE_LEN
      ? value.slice(0, MAX_VALUE_LEN) + '… (' + value.length + ' chars total)'
      : value;
  }

  /** dedupe, when given, is { key, location, baseTitle } consumed by
   * {@link mergeDuplicateFindings}: key groups repeats of the SAME check on the SAME underlying
   * value together (never across different checks), location is this one occurrence's evidence
   * line, baseTitle is the title with the location suffix stripped, used to rebuild a merged
   * title once more than one location shares a key. */
  function mk(
    title,
    severity,
    confidence,
    category,
    evidence,
    description,
    dedupe
  ) {
    const finding = {
      title,
      severity,
      confidence,
      category,
      evidence: truncate(evidence),
      description,
    };
    if (dedupe) {
      finding._dedupeKey = dedupe.key;
      finding._dedupeLocation = dedupe.location;
      finding._dedupeBaseTitle = dedupe.baseTitle;
    }
    return finding;
  }

  /** Builds the "opaque token" finding, shared by the flat top-level check in
   * {@link analyzeStorage} and the recursive JSON walk in {@link walkJsonForTokens} below, so
   * both report it identically regardless of how deep the value was found. path is the full
   * dot/bracket-joined location for the evidence line (just the key name for a flat value,
   * "authnResult.refresh_token" for something found inside a parsed JSON blob). The dedupe key
   * includes apiName (unlike analyzeJwt's), a localStorage and a sessionStorage copy of the same
   * value get DIFFERENT severities (MEDIUM vs LOW, see below) so they must stay separate
   * findings, only repeats within the SAME storage type collapse. */
  function opaqueTokenFinding(keyName, value, apiName, path) {
    if (isPublicByDesign(value)) {
      return mk(
        'Public-by-design key stored in ' + apiName + ': ' + path,
        'INFORMATION',
        'CERTAIN',
        'storage',
        apiName + '.' + path + ' = ' + truncate(value),
        'This looks like a publishable client-side API key (restricted by ' +
          'referrer/origin on the provider side, not a secret). No action needed.',
        {
          key: 'public-key:' + apiName + ':' + value,
          location: apiName + '.' + path,
          baseTitle: 'Public-by-design key stored in ' + apiName,
        }
      );
    }
    // sessionStorage is scoped to this one tab/browsing context and dies with it,
    // localStorage is shared across every tab of the origin and survives restarts, same
    // exploitability (XSS reads it either way), narrower window, one severity tier down.
    return mk(
      'Session/auth token stored in ' + apiName + ': ' + path,
      apiName === 'sessionStorage' ? 'LOW' : 'MEDIUM',
      'CERTAIN',
      'storage',
      apiName + '.' + path + ' = ' + truncate(value),
      apiName +
        ' has no HttpOnly-equivalent protection: any JavaScript ' +
        'on this page (including via XSS) can read this value directly. ' +
        (apiName === 'localStorage'
          ? 'localStorage also has no expiry and persists across tabs and restarts.'
          : 'sessionStorage is scoped to this tab and cleared when it closes, a narrower ' +
            'window than localStorage for the same underlying exposure.'),
      {
        key: 'opaque-token:' + apiName + ':' + value,
        location: apiName + '.' + path,
        baseTitle: 'Session/auth token stored in ' + apiName,
      }
    );
  }

  /** Recursively walks a parsed JSON value, applying the same JWT/opaque-token checks as the
   * flat top-level scan to every string leaf. Needed because plenty of OIDC/auth libraries
   * (angular-auth-oidc-client, oidc-client-ts, MSAL, Auth0 SPA SDK, ...) serialize their ENTIRE
   * token response, access_token/id_token/refresh_token included, as one JSON blob under a
   * single storage key (e.g. "0-client-biportal") whose own name looks nothing like a token and
   * whose own value fails the flat opaque-token charset check (it's JSON, not base64), hiding
   * every field inside it from the checks below otherwise. keyContext is the nearest enclosing
   * PROPERTY name (not array index) doing the isSensitiveKeyName gating, threaded separately
   * from path so an array of raw tokens under a sensitive key (e.g. "tokens": ["a...", "b..."])
   * still gates correctly even though "0"/"1" themselves aren't sensitive-looking names. depth is
   * capped defensively, JSON.parse can't produce real cycles but a pathologically deep payload
   * shouldn't be able to make this expensive. */
  function walkJsonForTokens(
    value,
    path,
    keyContext,
    apiName,
    findings,
    depth
  ) {
    if (depth > 8 || value === null || value === undefined) return;
    if (typeof value === 'string') {
      if (looksLikeJwt(value)) {
        findings.push(...analyzeJwt(value, apiName + '.' + path));
        return;
      }
      if (isSensitiveKeyName(keyContext) && looksLikeOpaqueToken(value)) {
        findings.push(opaqueTokenFinding(keyContext, value, apiName, path));
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, i) =>
        walkJsonForTokens(
          item,
          path + '[' + i + ']',
          keyContext,
          apiName,
          findings,
          depth + 1
        )
      );
      return;
    }
    if (typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) {
        walkJsonForTokens(v, path + '.' + k, k, apiName, findings, depth + 1);
      }
    }
  }

  /** Checks (1)+(2)-ish: real secrets/tokens/PII in localStorage/sessionStorage. */
  function analyzeStorage(storageDump, apiName) {
    const findings = [];
    for (const [key, value] of Object.entries(storageDump || {})) {
      if (typeof value !== 'string' || !value) continue;

      if (looksLikeJwt(value)) {
        findings.push(...analyzeJwt(value, apiName + '.' + key));
        continue;
      }

      if (isSensitiveKeyName(key) && looksLikeOpaqueToken(value)) {
        findings.push(opaqueTokenFinding(key, value, apiName, key));
        continue;
      }

      // Not a token itself, could still be a JSON blob hiding one, see walkJsonForTokens.
      const trimmed = value.trim();
      if (trimmed[0] === '{' || trimmed[0] === '[') {
        try {
          walkJsonForTokens(
            JSON.parse(trimmed),
            key,
            key,
            apiName,
            findings,
            0
          );
        } catch (e) {
          /* not actually valid JSON, nothing to walk */
        }
      }
    }
    return findings;
  }

  /** Rendered-DOM signals collected by content.js. Scoped deliberately narrow
   * to auth-token-shaped values on window globals, the same "headers/cookies/
   * auth only" line Quimera-burp's own BrowserDomAnalyzer already draws (see
   * that file's comments). Insecure forms, generic DOM secrets ("possible
   * secret in a hidden input/comment") and postMessage-without-origin-check
   * were all tried here and removed: none of them are headers, auth or
   * cookie findings, they read as unrelated noise mixed into that signal.
   * Do not re-add these as a blanket "DOM noise" category again. (Check 4,
   * target=_blank without rel=noopener, was removed earlier for a related
   * reason: every current-generation browser sets noopener implicitly by
   * default, so it isn't a live issue either.) */
  function analyzeDomSignals(dom) {
    const findings = [];
    if (!dom) return findings;

    for (const key of dom.windowGlobals || []) {
      if (isPublicByDesign(key.value)) continue;
      if (looksLikeJwt(key.value)) {
        findings.push(...analyzeJwt(key.value, 'window.' + key.name));
        continue;
      }
      if (looksLikeOpaqueToken(key.value)) {
        findings.push(
          mk(
            'Sensitive-looking value on window.' + key.name,
            'LOW',
            'FIRM',
            'dom',
            'window.' + key.name + ' = ' + truncate(key.value),
            'A global JavaScript variable with a credential-like name holds a ' +
              'token-like value. Any script running on this page (including via ' +
              'XSS) can read it. Confirm it is real token material.'
          )
        );
      }
    }

    return findings;
  }

  /** Collapses findings that carry the same {@link mk} dedupe key (same check, same underlying
   * secret value) into one, listing every location it was found at instead of repeating the
   * whole finding once per location. Needed because the recursive JSON-blob walk in
   * {@link walkJsonForTokens} routinely surfaces the exact same token more than once, OIDC/auth
   * libraries commonly store the raw access token under two different fields of their own state
   * blob (angular-auth-oidc-client's authnResult.access_token and authzData are frequently the
   * identical string), which used to read as the same vulnerability reported 2-3x in a row.
   * Findings with no dedupe key (everything outside analyzeJwt/opaqueTokenFinding) pass through
   * untouched, in their original relative order. */
  function mergeDuplicateFindings(findings) {
    const merged = new Map(); // dedupeKey -> finding (first occurrence, mutated in place)
    const result = [];
    for (const f of findings) {
      if (!f._dedupeKey) {
        result.push(f);
        continue;
      }
      const existing = merged.get(f._dedupeKey);
      if (!existing) {
        f._locations = [f._dedupeLocation];
        merged.set(f._dedupeKey, f);
        result.push(f);
      } else {
        existing._locations.push(f._dedupeLocation);
      }
    }
    for (const f of result) {
      if (!f._locations) continue; // not a dedupe-tracked finding
      if (f._locations.length > 1) {
        f.title =
          f._dedupeBaseTitle +
          ': found at ' +
          f._locations.length +
          ' locations';
        f.evidence =
          f._locations.map(loc => '- ' + loc).join('\n') +
          (f.evidence ? '\n\nValue: ' + f.evidence : '');
      }
      delete f._dedupeKey;
      delete f._dedupeLocation;
      delete f._dedupeBaseTitle;
      delete f._locations;
    }
    return result;
  }

  /**
   * Runs every Phase-1 check over a collected payload.
   * @param {object} payload see content.js for the shape.
   * @return {Array<object>} findings, most-severe first.
   */
  function analyze(payload) {
    let findings = [];
    findings.push(...analyzeStorage(payload.localStorage, 'localStorage'));
    findings.push(...analyzeStorage(payload.sessionStorage, 'sessionStorage'));
    findings.push(...analyzeDomSignals(payload.dom));
    findings = mergeDuplicateFindings(findings);

    const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFORMATION: 3 };
    findings.sort(
      (a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9)
    );
    return findings;
  }

  global.QuimeraEngine = {
    analyze,
    looksLikeJwt,
    decodeJwt,
    isSensitiveKeyName,
    looksLikeOpaqueToken,
  };
})(typeof window !== 'undefined' ? window : globalThis);
