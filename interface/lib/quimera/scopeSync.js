import { normalizeScopeEntry, scopeEntryMatchesHost } from './scope.js';

/** Reconciles a fresh Burp snapshot without granting any new browser access. */
export function reconcileBurpScope(options, remoteHosts, removedHosts = []) {
  const remote = [
    ...new Set((remoteHosts || []).map(normalizeScopeEntry)),
  ].filter(Boolean);
  const manual = options.manualScopeHosts || [];
  const removed = [...new Set(removedHosts.map(normalizeScopeEntry))].filter(
    Boolean
  );
  const authorized = (options.burpScopeHosts || []).filter(
    host => !removed.includes(host)
  );
  const previousPending = (options.burpScopePendingHosts || []).filter(
    host => !removed.includes(host)
  );
  const pending = [...new Set([...previousPending, ...remote])].filter(
    host =>
      !authorized.includes(host) &&
      !manual.some(entry => scopeEntryMatchesHost(entry, host))
  );
  return {
    ...options,
    burpScopeHosts: authorized,
    burpScopePendingHosts: pending,
    scopeHosts: [...new Set([...manual, ...authorized])],
  };
}

/** Commits only hosts that were present in the last authenticated pending snapshot. */
export function authorizePendingBurpHosts(options, requestedHosts) {
  const requested = [
    ...new Set((requestedHosts || []).map(normalizeScopeEntry)),
  ].filter(Boolean);
  const pendingBefore = options.burpScopePendingHosts || [];
  const approved = pendingBefore.filter(host => requested.includes(host));
  const authorized = [
    ...new Set([...(options.burpScopeHosts || []), ...approved]),
  ];
  const pending = pendingBefore.filter(host => !approved.includes(host));
  return {
    ...options,
    burpScopeHosts: authorized,
    burpScopePendingHosts: pending,
    scopeHosts: [
      ...new Set([...(options.manualScopeHosts || []), ...authorized]),
    ],
  };
}
