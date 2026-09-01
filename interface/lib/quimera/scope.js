const DOMAIN = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;

/** Normalizes one exact host or a leading-wildcard host such as *example.com. */
export function normalizeScopeEntry(value) {
  const entry = String(value || '')
    .trim()
    .toLowerCase();
  const wildcard = entry.startsWith('*');
  const base = wildcard ? entry.slice(1) : entry;
  if (
    !DOMAIN.test(base) ||
    (!base.includes('.') && base !== 'localhost') ||
    base.includes('..') ||
    (wildcard && (base === 'localhost' || /^\d+(?:\.\d+){3}$/.test(base)))
  )
    return null;
  return wildcard ? `*${base}` : base;
}

/** Returns true for an exact host, or the apex and dot-bound subdomains of *example.com. */
export function scopeEntryMatchesHost(entry, hostname) {
  const normalized = normalizeScopeEntry(entry);
  const host = String(hostname || '').toLowerCase();
  if (!normalized) return false;
  if (!normalized.startsWith('*')) return host === normalized;
  const base = normalized.slice(1);
  return host === base || host.endsWith(`.${base}`);
}

/** Converts a scope entry to the narrow browser match patterns it needs. */
export function scopeEntryOrigins(entry) {
  const normalized = normalizeScopeEntry(entry);
  if (!normalized) return [];
  const base = normalized.startsWith('*') ? normalized.slice(1) : normalized;
  const hosts = normalized.startsWith('*') ? [base, `*.${base}`] : [base];
  return hosts.flatMap(host => [`http://${host}/*`, `https://${host}/*`]);
}
