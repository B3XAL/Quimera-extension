# Mozilla Add-ons source build instructions

This source package corresponds to Quimera for Firefox version 1.0.3.

## Environment

- Ubuntu 24.04 LTS (or another Unix-like environment)
- Node.js 24.x
- npm 11.x
- `zip` available on `PATH`

No proprietary or web-based build tool is required. Dependencies are installed from the npm
registry using the included `package-lock.json`.

## Build

From the directory containing this file, run:

```sh
npm ci
npm run build
```

The exact Firefox submission package is generated at:

```text
dist/1.0.3/quimera-firefox-1.0.3.zip
```

The build does not minify, bundle, transpile, or obfuscate JavaScript. `scripts/build.mjs` copies
the readable source files, uses `manifest.firefox.json` as the generated `manifest.json`, replaces
the `@@browser_name` build placeholder with `firefox`, and creates the ZIP archive.

`npm run build` first runs ESLint and then generates the Firefox, Chrome, Edge, Opera, and Safari
build directories. Only the Firefox ZIP named above corresponds to this AMO submission.

Optional verification tests can be run with:

```sh
npm test
```

The separate Quimera extension for Burp Suite is optional runtime companion software and is not
part of, or required to build, this Firefox extension.
