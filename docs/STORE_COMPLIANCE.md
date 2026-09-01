# Browser-store readiness matrix

This file is a pre-submission checklist, not store approval. Recheck the linked policies on every
release because store rules change.

| Store | Official review areas | Repository evidence | Remaining release gate |
|---|---|---|---|
| Chrome Web Store | [Program policies](https://developer.chrome.com/docs/webstore/program-policies/) and [privacy](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq/) | Single security-testing purpose, MV3, local code, host access disclosed at install (see below), privacy policy, no ads | Complete Data Usage disclosure, screenshots, listing copy and packed manual test |
| Firefox Add-ons | [Add-on policies](https://extensionworkshop.com/documentation/publish/add-on-policies/) | Firefox manifest declares `data_collection_permissions`; min Firefox 140; source is readable | Validate/lint and sign exact ZIP; ensure AMO questionnaire matches `PRIVACY.md` |
| Microsoft Edge | [Policies](https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies) | Dedicated Edge manifest/package, single purpose and permission rationale below | Partner Center privacy URL, support URL, assets and certification test |
| Opera Add-ons | [Acceptance criteria](https://dev.opera.com/extensions/publishing-guidelines/) | No obfuscation, ads, affiliate code or unused packaged sources; dedicated ZIP | Manual Opera test, listing assets and reviewer notes |
| Safari macOS | [Safari Web Extensions](https://developer.apple.com/documentation/safariservices/safari_web_extensions) | Web-extension target and Xcode wrapper exist | Must build/sign/notarize and validate in current Xcode on macOS; not CI-verified here |

## Single purpose and permission rationale

The sole purpose is inspecting and managing browser-side authentication state during authorized
web security testing. `cookies` reads/edits cookies; `storage` stores settings/findings; `tabs`
identifies the active test page; `scripting` is retained for the unregister-only cleanup of
registrations left by older builds; `sidePanel` exposes the same UI in supporting Chromium
browsers. `alarms` performs a one-minute local refresh only while Burp scope synchronization is
enabled.

Host permissions differ by browser. Chrome, Edge, Opera and Safari declare `<all_urls>` plus the
loopback hosts as mandatory `host_permissions`, so the browser shows the broad-access warning once
at install time and the page collector (Storage/Vulns tab data) runs from then on with no further
per-host prompt; this replaced an earlier per-host `scripting.registerContentScripts` design that
proved unreliable across MV3 service-worker restarts. Firefox keeps `<all_urls>` as an optional
permission, requested from a user gesture in Options or the popup's bridge widget, with only the
loopback hosts mandatory; this matches Firefox's `data_collection_permissions` questionnaire, which
still lists `authenticationInfo`/`browsingActivity`/`websiteContent` as required only once that
optional grant is made.

On every browser, granting host access only starts the client-side Storage/Vulns detection local to
the popup; it does not by itself send anything off-device. Delivery to the Quimera Burp bridge is a
separate, independently gated step: the bridge stays disabled until a pairing token is set, and even
once paired it enforces Burp Target Scope before accepting a snapshot. Remove platform-only
permissions from manifests for platforms that do not implement them.

## Data declaration

Potentially processed categories are authentication information, browsing activity (the current
authorized URL) and website content (selected storage/runtime values). They are used only for the
user-facing security analysis, are not sold or used for advertising/credit/profiling, and are not
sent off-device. Pairing with the optional local Burp bridge is a user-initiated local transfer.

## Pre-release test matrix

For every target, install the exact generated archive in a clean profile; verify first-run has no
site access and no bridge traffic, permission grant/revoke, exact-host isolation, cookie CRUD,
Storage/Vulns views, incognito behavior, bridge good/bad/missing token, port failure, offline use,
upgrade and uninstall. Inspect the package for source maps, secrets, stale ads, unexpected URLs and
unreferenced files. Safari requires macOS/Xcode testing; mobile targets are out of scope for 1.0.0.

Store assets still require human-created screenshots that show real UI without real credentials,
a 128px icon (plus each store's requested sizes), short/long descriptions, support/contact URLs,
privacy-policy URL, category, release notes and reviewer instructions explaining the authorized
testing use case and optional Burp pairing.

## Hosted privacy policy

Chrome and Firefox require the privacy policy at a public HTTPS URL, not only in-repo Markdown.
`docs/privacy/index.html` mirrors `PRIVACY.md`, including the Limited Use declaration, and is
ready to serve as-is. Once this repository is public: Settings > Pages > Source: "Deploy from a
branch" > Branch: `main`, folder `/docs`. The policy URL is then
`https://b3xal.github.io/Quimera-extension/privacy/`. No build step or Actions workflow is
required for this. Use that exact URL in every store's privacy-policy field.

See `STORE_LISTING.md` for exact submission copy per store.
