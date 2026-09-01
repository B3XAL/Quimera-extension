<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="readme/quimera-logo-card.png">
  <img src="readme/quimera-logo.png" alt="Quimera logo" width="480">
</picture>

# Quimera

**A cookie manager that also watches your own browser for the things a proxy can never see.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-orange.svg)](manifest.chrome.json)
[![Chrome · Firefox · Edge · Opera · Safari](https://img.shields.io/badge/Browsers-Chrome%20%C2%B7%20Firefox%20%C2%B7%20Edge%20%C2%B7%20Opera%20%C2%B7%20Safari-informational.svg)](#installing-unpacked-for-personal-use)

</div>

---

A proxy only ever sees what goes over the wire. It never sees the token a SPA quietly stashed in
`localStorage` after the HTTP response was already rendered, the cookie that claims `HttpOnly` but
is actually readable from `document.cookie` because someone set it wrong, or the OIDC token
response an auth library buried three levels deep inside a JSON blob under one innocuous-looking
key. Quimera is a full cookie manager first, and a small, real vulnerability engine running
entirely inside the page second, so it catches what response-body analysis has to guess at.

## Why it exists

This started as a fork of [Cookie-Editor](https://cookie-editor.com/), still fully GPL-3.0 and
still crediting its original author, because the cookie-jar engine underneath it (fast, clean,
already handles every browser's quirks) didn't need reinventing. What Quimera adds on top is the
part a cookie editor was never meant to do: read the page's actual runtime state, the way an
attacker's own injected script would, and flag what's actually reachable instead of what merely
looks suspicious in a name. A key called `authToken` sitting in Web Storage is an easy heuristic
hit; a raw OIDC token response silently nested inside a completely unrelated-looking blob is the
kind of thing that survives most reviews, and it doesn't survive Quimera's.

## Features

### Cookie management (inherited from Cookie-Editor)
- Create, edit, delete cookies for the current tab, with full attribute control (Secure,
  HttpOnly*, SameSite, Domain, Path, Expiration).
- Import/export as JSON, header string, or Netscape cookie-file format.
- Works from the popup, a dedicated side panel, or DevTools, whichever fits your workflow.

*(*Cookies actually set as `HttpOnly` can't be read or written by any extension, by browser design,
this is a feature, not a Quimera limitation.)*

### Storage tab
Shows the real, live `localStorage`/`sessionStorage` contents of the page you're on, not a guess
reconstructed from an HTTP response body. If it's in the page right now, you see it.

### Vulns tab
A small client-side vulnerability engine, running entirely in the browser, no server needed, that
flags things a proxy can never see:
- Real secrets/JWTs sitting in Web Storage or in credential-shaped `window` globals.
- Cookies that are actually readable by JavaScript despite the site claiming `HttpOnly` somewhere
  else.
- Storage values that are themselves a JSON blob get walked **recursively**, not just checked flat,
  so a token buried inside one, `angular-auth-oidc-client`, `oidc-client-ts`, MSAL and similar OIDC
  libraries store the *entire* token response (access/refresh/id token included) as one JSON string
  under a single key, still gets found even though neither the key's name nor its raw value look
  like a token on their own.
- Severity accounts for where a value actually lives: `localStorage` (persistent, readable by any
  future XSS at leisure) scores higher than `sessionStorage` (tab-scoped, gone once the tab
  closes).

Deliberately scoped to headers/cookies/auth only, generic DOM-secret scanning, insecure-form
scanning, and postMessage origin-check scanning were tried and removed, see `content/engine.js`'s
own comments for what and why.

### Bridge to Quimera Burp (optional)
When the [Quimera Burp extension](https://github.com/B3XAL/Quimera) is running on the same
machine, every page snapshot is also sent to it over a local loopback connection for deeper
analysis (CSP, known auth-SDK signatures, tech fingerprinting). Deliberately one-way: whatever
Quimera-burp's own analysis finds shows up in *its* Logger/Issues, not mirrored back into this
extension's Vulns tab, which only ever shows what the extension itself detected. Off by default,
requires explicit pairing: enable the bridge in Burp and copy its generated token into Options.
Leave it disabled and the extension keeps working standalone.

Host access works differently per browser. On Chrome, Edge, Opera and Safari, `<all_urls>` is
requested once at install (the browser shows this as its normal install-time permission warning),
so the Storage/Vulns collector runs on every regular HTTP(S) page from then on with no further
prompt. On Firefox, `<all_urls>` stays an optional permission: grant it once from **Options** or
from the popup's bridge widget when pairing. On every browser, granting host access only starts
local collection for the Storage/Vulns tab; sending anything to the Burp bridge is a separate,
independently gated step (see below), and the bridge itself discards snapshots outside Burp Target
Scope regardless. Optional Burp Target Scope synchronization imports observed in-scope hosts as
pending Firefox permission candidates; it never grants browser access silently. Options also
controls bridge pairing and individual collectors.

## Pairing with Quimera Burp, step by step

Both sides are off by default and require a few clicks to connect. Prerequisites: [Quimera for
Burp Suite](https://github.com/B3XAL/Quimera) is loaded and running, and this extension is
installed and its Options page is reachable.

### 1. Generate a token in Burp

1. Open the **Quimera** tab in Burp Suite's top tab bar.
2. Inside it, open the **Settings** tab.
3. Click the **Browser Bridge...** button. This opens the "Quimera - Browser Bridge" dialog.
4. Check **Enable Browser Bridge**.
5. Leave **Port** at its default, `8199`, unless that port is already used by something else on
   your machine; the extension defaults to the same value.
6. Under **Pairing token (required)**, click **Generate**, then **Copy** to put the token on your
   clipboard.
7. Click **Apply**. The status line above should switch to "● Running on 127.0.0.1:8199" (or
   whatever port you chose). If it says "Failed to start", something else already has that port,
   pick a different one on both sides.

### 2. Paste the token into the extension

1. Click the Quimera icon in your browser toolbar and open **Options** (or right-click the icon →
   Options, or find it from `chrome://extensions`/`about:addons`).
2. In the **Quimera Bridge** section, turn on **Enable Bridge to Quimera (Burp)**.
3. Paste the token you copied from Burp into **Pairing Token**, right below it.
4. Only if you changed the port in Burp, update **Bridge Port** here to match; otherwise leave it
   at `8199`.
5. Click **Check now** next to **Connection status**. It should read "Connected to Quimera". If it
   doesn't, see Troubleshooting below before moving on.

### 3. Give it something to actually see

Pairing alone doesn't collect anything yet, the extension still needs permission to read a given
site, same as any browser extension:
- Simplest: click **Allow access to all websites** once in Options.
- More conservative: list specific hosts under **Authorized hosts**, one per line
  (`example.com`, or `*example.com` to include every subdomain too).
- Or turn on **Synchronize Burp Target Scope** and click **Sync and authorize new hosts**, which
  offers hosts Quimera has already seen in Burp traffic and are currently in Target Scope as
  candidates, no full `<all_urls>` grant required.

### 4. Confirm it's actually working

Browse to a page you've authorized. In Burp's **Quimera** tab, findings sourced from the browser
(real `localStorage`/`sessionStorage`/cookie values, or auth-shaped `window` globals) start showing
up the same way HTTP-driven findings do, marked as browser-sourced. If a page's host isn't in Burp
Target Scope, the bridge silently discards what the browser sent for it, by design, not a bug.

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Not connected (Quimera not running, or bridge disabled/blocked)" | Burp isn't running, the Browser Bridge dialog's "Enable Browser Bridge" is unchecked, or its status line says "Failed to start" (port already in use, e.g. two Burp instances). |
| "Paste the pairing token shown by the Quimera Burp extension first" | The Pairing Token field is empty or under 32 characters. Go back to Burp's Browser Bridge dialog and click **Copy** again. |
| Connected, but nothing ever shows up in Burp | Check step 3 (the extension needs host permission for that page) and confirm the page's host is actually in Burp's Target Scope. |
| It worked, then stopped | The token was probably regenerated in Burp (rotating it invalidates the old one immediately). Copy the new one into Options again. |
| Port fields don't agree | The **Port** value in Burp's dialog and **Bridge Port** in the extension's Options must be identical. |

## Installing (unpacked, for personal use)

**Chrome / Edge / Brave / Opera:**
1. Open `chrome://extensions` (or the equivalent `edge://extensions`, `opera://extensions`).
2. Turn on "Developer mode" (top right).
3. Click "Load unpacked" and select this folder.
4. Copy the browser-specific manifest (`manifest.chrome.json`, `manifest.edge.json`, or
   `manifest.opera.json`) to `manifest.json` first if the browser doesn't pick it up
   automatically, some Chromium builds require the file to literally be named `manifest.json`.

**Firefox:**
1. Open `about:debugging#/runtime/this-firefox`.
2. Click "Load Temporary Add-on…" and select `manifest.firefox.json` (or a copy of it named
   `manifest.json` in this folder).
3. Temporary add-ons are removed when Firefox restarts; reload it from `about:debugging` again
   after restarting, or package it properly for a permanent install.

**Safari:** the native wrapper app lives in `safari/Quimera/`, an Xcode project. Open it in Xcode,
set your own Apple Developer Team under Signing & Capabilities (the shipped project has none
configured), run `npm run build:safari`, and build the wrapper in Xcode.

The manifests request host access optionally. Add only the exact authorized test hosts in Options;
an empty list means no page capture. You can revoke access at any time in browser settings.

## Testing the vulnerability engine

Open `test/seed.html` (serve it, e.g. `python3 -m http.server` from `test/`, so it has a real HTTP
origin) with the extension installed, then open the Vulns tab. It seeds one example of every check
still in scope: a JWT with `alg:none`, a JWT with no `exp`, and an opaque token in Web Storage and
in a window global.

## Building from source

```bash
npm ci
npm test
npm run lint
npm run build          # builds targets into build/<browser>/ and store ZIPs into dist/<version>/
npm run build:safari   # Safari target only, feeds the Xcode project in safari/Quimera/
```

## Architecture

```
content/            content scripts: DOM/window-global collection (content.js, inject-mainworld.js,
                     mainworld-loader.js) and the client-side vulnerability engine (engine.js)
interface/lib/       shared background-script libraries: browser detection, permission handling,
                     Netscape-format cookie import/export
interface/lib/quimera/  Quimera-specific additions: the Burp bridge client, shared constants, cookie
                     checks
interface/popup/    the popup UI, including quimera-tabs.js (Storage/Vulns tab wiring on top of
                     Cookie-Editor's own cookie-list UI)
interface/options/  the Options page (bridge port/token, host scoping, collector toggles, About)
interface/devtools/ the DevTools panel variant of the same UI
interface/sidepanel/ the side-panel variant of the same UI
safari/Quimera/     the native Safari wrapper app (Xcode project)
```

## Credit

Quimera is a fork of [Cookie-Editor](https://cookie-editor.com/) by Christophe Gagnier, published
under [the GPL-3.0 license](https://github.com/Moustachauve/cookie-editor/blob/master/LICENSE).
Cookie-Editor itself is a separate, independently published extension for creating/editing/
deleting cookies, available on the Chrome Web Store, Firefox Add-ons, the App Store, Microsoft
Store and Opera Add-ons, see its own site for those links, this fork isn't published on any of
them.

## Feature suggestions or bug reports

[Find me on GitHub](https://github.com/B3XAL).

## License

GPL-3.0, see [`LICENSE`](LICENSE). Use it, fork it, modify it, just keep it open: any distributed
fork or derivative must stay GPL-3.0, credit Cookie-Editor as the base it's built on, and make its
source available.
