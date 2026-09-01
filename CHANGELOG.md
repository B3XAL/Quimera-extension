# Changelog

## 1.0.3

- Fixed the content script running twice on Firefox after a background restart (Firefox now uses
  a background page instead of a module background script, avoiding duplicate collection).
- Replaced unreliable per-host dynamic content-script registration with static manifest
  declarations; browser host permissions alone now decide where the collector runs.
- Fixed a snapshot never being retried after the Burp bridge came back online or the pairing
  token changed, by tracking delivery acknowledgement instead of a fire-and-forget message.
- Added detection for identifying data (emails, phone numbers, person names, usernames, stable
  UUIDs) stored client-side, reported separately from authentication-secret findings.
- Fixed the opaque-token check misfiring on application routes (for example
  `/Account/ResetPassword`).
- Fixed the popup clipping the bridge widget dropdown.
- Chrome, Edge, Opera and Safari now request `<all_urls>` as a mandatory permission at install
  instead of an optional one requested later from Options; Firefox keeps it optional.

## 1.0.0 - unreleased

- Added deterministic multi-browser packaging and CI verification.
- Made page capture and the Burp bridge disabled until explicitly configured.
- Replaced blanket mandatory host access with optional host permissions.
- Made bridge authentication mandatory and aligned it with the versioned Burp API.
- Added Firefox data-collection declarations and removed advertising/affiliate code.
- Added privacy, security and store-readiness documentation.

