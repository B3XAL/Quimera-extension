/**
 * Cookie-flag findings computed from the browser's own `cookies` API
 * (authoritative: includes HttpOnly cookies too, unlike document.cookie).
 * ES module, used from the background script and, on demand, the popup.
 *
 * This is the ground-truth counterpart to Quimera's Set-Cookie-header-based
 * CookieAnalyzer: the browser tells us the real flags instead of Quimera
 * inferring them from a header string.
 */

const SESSION_NAME_KEYWORDS = [
  'session',
  'sessid',
  'phpsessid',
  'auth',
  'token',
  'jwt',
  'sso',
  'login',
];

const TRACKING_PREFIXES = [
  '_ga',
  '_gid',
  '_gat',
  '_fbp',
  '_fbc',
  '_hj',
  '_clck',
  '_clsk',
  '__cf',
  'mp_',
];

function isTrackingCookie(name) {
  const lower = (name || '').toLowerCase();
  return TRACKING_PREFIXES.some(p => lower.startsWith(p));
}

function looksLikeSessionCookie(name) {
  const lower = (name || '').toLowerCase();
  return SESSION_NAME_KEYWORDS.some(kw => lower.includes(kw));
}

/** cookieName is a structured field (not just embedded in the title text) so the Quimera-burp
 * bridge can reliably cross-reference it against what it already saw via real Set-Cookie traffic
 * (see BrowserBridgeServer/HeaderAnalysisEngine#hasSeenCookieViaHttp) without having to parse it
 * back out of a human-readable string. */
function mk(cookieName, title, severity, confidence, evidence, description) {
  return {
    title,
    severity,
    confidence,
    category: 'cookie',
    cookieName,
    evidence,
    description,
  };
}

/**
 * @param {Array<object>} cookies from browser.cookies.getAll(), real flags.
 * @param {Array<string>} jsCookieNames names readable via document.cookie
 *   on the page that was collected (ground truth for HttpOnly).
 * @return {Array<object>} findings.
 */
export function analyzeCookies(cookies, jsCookieNames) {
  const findings = [];
  const jsReadable = new Set(jsCookieNames || []);

  for (const c of cookies || []) {
    if (isTrackingCookie(c.name)) continue;

    // Ground truth: browser.cookies says httpOnly=false. Cross-referencing
    // against document.cookie just confirms the flag is doing what it says;
    // the flag itself is already authoritative, so this fires on the flag
    // alone rather than requiring both signals to agree.
    if (!c.httpOnly && looksLikeSessionCookie(c.name)) {
      findings.push(
        mk(
          c.name,
          'Session cookie without HttpOnly (browser-confirmed): ' + c.name,
          'MEDIUM',
          'CERTAIN',
          c.name +
            ' httpOnly=false' +
            (jsReadable.has(c.name)
              ? ', confirmed readable via document.cookie'
              : ''),
          'The browser\'s own cookie store confirms "' +
            c.name +
            '" is not ' +
            'HttpOnly. Any JavaScript on this origin, including via XSS, can ' +
            "read this cookie's value directly."
        )
      );
    }

    if (!c.secure) {
      findings.push(
        mk(
          c.name,
          'Cookie without Secure flag: ' + c.name,
          'MEDIUM',
          'CERTAIN',
          c.name + ' secure=false',
          'This cookie can be sent over a plain HTTP connection, exposing it ' +
            'to network-level interception on any non-HTTPS request to this domain.'
        )
      );
    }

    if (c.sameSite === 'no_restriction' && !c.secure) {
      findings.push(
        mk(
          c.name,
          'SameSite=None without Secure: ' + c.name,
          'MEDIUM',
          'CERTAIN',
          c.name + ' sameSite=no_restriction, secure=false',
          'SameSite=None cookies are sent on cross-site requests; without ' +
            'Secure this is also exposed on plain HTTP, combining CSRF-adjacent ' +
            'exposure with network interception risk.'
        )
      );
    }

    if (c.domain && c.domain.startsWith('.') && !c.hostOnly) {
      findings.push(
        mk(
          c.name,
          'Cookie scoped to a wide domain: ' + c.name,
          'LOW',
          'CERTAIN',
          c.name + ' domain=' + c.domain,
          'This cookie is scoped with a leading dot / non-host-only domain, ' +
            'sent to this domain and every subdomain. Any subdomain compromise ' +
            'or a permissive subdomain can read or set this cookie.'
        )
      );
    }
  }

  return findings;
}
