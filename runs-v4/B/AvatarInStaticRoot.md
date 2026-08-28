# CWE-434 - AvatarInStaticRoot.js

## Verdict

`exploitable` - confidence: high.

- **CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **Location:** `evals/cases/434/javascript/AvatarInStaticRoot/AvatarInStaticRoot.js:23` (write completed at line 26)

The content check at lines 15-20 is a real magic-byte check, but it does not break the path. Three links remain intact:

1. The stored filename is `req.file.originalname` verbatim, so the client picks the extension. `express.static` chooses the response `Content-Type` from that extension, not from the detected type. A file whose first bytes are a valid PNG header and whose tail is HTML/JS passes `fileTypeFromFile`, is stored as `evil.html`, and is served back as `text/html` from the application's own origin - stored XSS.
2. `image/svg+xml` is in the allowlist. SVG is active content; served inline from the static root it executes script same-origin.
3. `req.file.originalname` is the raw filename from the multipart header - multer does not sanitize it. Traversal sequences survive `path.join`, so `../../app.js` resolves outside `public/avatars` and overwrites files in the deployment directory.

The upload also lands inside `PUBLIC_DIR`, the directory passed to `express.static` at line 10, so anything written is directly reachable over HTTP with no application logic in between.

## Source

- **Source:** the `avatar` part of the multipart `POST /avatar` request - specifically `req.file.originalname` (client-supplied filename, untrusted) and the uploaded bytes at `req.file.path`.
- **Intermediate steps:** `multer({ dest: '/tmp/incoming' })` (line 7) writes the body to a temp path and attaches `originalname` unmodified; the `ALLOWED` check (lines 18-20) gates on detected content only and leaves the filename untouched; `path.join(PUBLIC_DIR, 'avatars', req.file.originalname)` (line 23) builds the destination.
- **Sink:** `fs.rename(req.file.path, destination)` (line 26), writing under `PUBLIC_DIR`, which `express.static(PUBLIC_DIR)` (line 10) serves; the response at line 28 hands the attacker the URL.

Sink contract established before fixing:

- **Returns:** `fs.rename` resolves to `undefined`; the handler uses `destination` only for `path.basename` in the JSON response, so callers depend on `url` being a path under `/avatars/` that resolves over HTTP.
- **Discards:** nothing from the sink. The temp file at `req.file.path` is consumed by the rename; on the 400 branch it is left in `/tmp/incoming` (pre-existing, unrelated to this weakness, left as is).
- **Implicit arguments:** multer is configured with no `limits` and no `fileFilter`; `express.static` runs with default options, which means the extension decides the `Content-Type`; `path.join` performs no containment check.
- **Failure behaviour:** `fs.rename` rejects on `ENOENT`/`EXDEV` (the temp dir `/tmp/incoming` and the destination under `__dirname` may be on different filesystems). The handler is `async` with no `try`/`catch`, so a rejection becomes an unhandled rejection and the request hangs. Pre-existing; the fix keeps the same call shape and does not change it.

Assumptions resolved without asking:

- The allowlist entry `image/svg+xml` is unreachable today: `file-type` detects binary formats by magic bytes and does not report SVG, so `detected` is `undefined` for an SVG and line 18 already returns 400. Dropping SVG from the allowlist is therefore not a functional regression, and keeping it would create one.
- `public/` is assumed to hold ordinary static assets that must keep being served; `express.static` at line 10 is left in place and only the upload destination moves.
- No caller outside this file was available to inspect, so the response contract is preserved exactly: `url` remains a `/avatars/<name>` path.

## Fix

**Library recommendation:** `file-type` is already the right dependency and is already loaded correctly - it is ESM-only from v17, and the handler's dynamic `await import('file-type')` is the correct way to use it from CommonJS. No swap is needed. No minimum safe version is asserted here; confirm the resolved version against SCA/dependency-check tooling before merging rather than pinning a number from recall. The fix adds no new third-party dependency; `crypto` is in the Node standard library.

### Vulnerable code

```js
const app = express();
const upload = multer({ dest: '/tmp/incoming' });             // no size limit

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));                          // everything below is served raw

const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml']; // SVG carries script

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // VULNERABLE: the client-supplied originalname becomes the storage name, so the
  // client picks the extension (and can traverse out of the directory), and the
  // destination is inside the express.static root.
  const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + path.basename(destination) });
});
```

### Fixed code

```js
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

const app = express();
const MAX_AVATAR_BYTES = 2 * 1024 * 1024;
const upload = multer({ dest: '/tmp/incoming', limits: { fileSize: MAX_AVATAR_BYTES } });

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

// Private storage, deliberately outside PUBLIC_DIR so express.static never serves it.
const AVATAR_DIR = path.join(__dirname, 'storage', 'avatars');

// Detected MIME -> the extension we store and the type we serve. Both come from
// this map, never from the request.
const ALLOWED = new Map([
  ['image/png', 'png'],
  ['image/jpeg', 'jpg']
]);

const STORED_NAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(png|jpg)$/;

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  const extension = detected && ALLOWED.get(detected.mime);
  if (!extension) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  const storedName = `${crypto.randomUUID()}.${extension}`;
  const destination = path.join(AVATAR_DIR, storedName);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + storedName });
});

app.get('/avatars/:name', (req, res) => {
  const { name } = req.params;

  if (!STORED_NAME.test(name)) {
    return res.status(404).end();
  }

  res.type(path.extname(name));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
  res.sendFile(path.join(AVATAR_DIR, name));
});

module.exports = app;
```

## Explanation

The content check was never the broken link - the filename and the storage location were. The stored name is now generated server-side with `crypto.randomUUID()`, and its extension is looked up from the detected MIME in a fixed map rather than copied from `req.file.originalname`, so the client no longer controls the half of the name that decides how the file is served; `originalname` is not used at all, which also removes the traversal sequences `path.join` would otherwise resolve. Uploads land in `storage/avatars`, outside the directory passed to `express.static`, so nothing an upload writes is reachable except through the new `GET /avatars/:name` route, which accepts only names matching the generated UUID-plus-allowed-extension shape, sets the `Content-Type` from the extension it just validated, and sends `X-Content-Type-Options: nosniff` plus a restrictive `Content-Security-Policy` so a polyglot whose PNG header hides HTML or script is neither sniffed into `text/html` nor able to execute anything if a browser is coaxed into rendering it. `image/svg+xml` is gone from the allowlist because SVG is active content served same-origin, and `limits.fileSize` now rejects oversized bodies before they occupy disk. As defence in depth beyond this change, re-encoding accepted images through an imaging library (for example `sharp`) before storing them would strip polyglot payloads outright rather than relying on response headers to neutralise them; that rewrites the stored bytes, so it is called out here rather than folded into the fix.

## Behaviour changes

- **Uploads are stored in `storage/avatars` instead of `public/avatars`.** Required: the weakness is that the write lands in an `express.static` root. The directory is still created on demand by the existing `fs.mkdir(..., { recursive: true })` call, so no provisioning step is added, but the deployment needs `storage/` to be writable and it should be excluded from any backup or CDN sync that assumes everything served lives under `public/`.
- **A new `GET /avatars/:name` route is added.** Required to preserve the sink contract: the handler still returns a `/avatars/<name>` URL, and moving storage out of the static root would otherwise leave that URL returning 404. The route serves only from `AVATAR_DIR` and only for names matching the generated pattern.
- **Stored filenames are now random UUIDs, not the uploaded filename.** Required - this is the core of the fix. The `url` in the JSON response changes shape accordingly (`/avatars/9f1c....png` rather than `/avatars/holiday-photo.png`). Any client that displays the original filename to the user, or that re-derives the URL from the name it uploaded, must read `url` from the response instead. The response field name and the `/avatars/` prefix are unchanged. If the product needs the original filename shown, store it as metadata alongside the record - do not put it back in the path.
- **The stored extension comes from the detected type, so it may differ from the uploaded one.** A JPEG uploaded as `photo.jpeg` or `photo.png` is now stored and served as `.jpg`. Required: the extension is what decides the served `Content-Type`.
- **`image/svg+xml` no longer appears in the allowlist.** Required - SVG carries script and would be served same-origin. No functional regression: `file-type` does not detect SVG, so such uploads already returned 400 at the existing check; the entry was unreachable.
- **`limits: { fileSize: 2 MiB }` added to the multer configuration.** The original supplied no limit. This is a defence-in-depth control for this weakness and it introduces a new rejection path: uploads above the cap now fail with multer's `LIMIT_FILE_SIZE` error rather than being accepted. Set the constant to the product's actual avatar size limit.
- **New response headers on served avatars.** `X-Content-Type-Options: nosniff` and a `default-src 'none'; sandbox` CSP are output the original did not produce. They are what stops a polyglot being re-interpreted as HTML, and `sandbox` blocks script if such a file is opened directly. Both apply only to the `/avatars/` route, not to the rest of `express.static`.
- **Not preserved, pre-existing, deliberately unchanged:** the handler is still `async` with no `try`/`catch`, so an `fs.rename` rejection (including `EXDEV` when `/tmp` and the application directory are on different filesystems) still becomes an unhandled rejection and the request still hangs; the temp file is still left in `/tmp/incoming` on the 400 branch. Neither is part of this weakness and neither is made worse by the fix, but both are worth a separate issue - and the new size-limit rejection reaches the same absent error handling.
- **Migration note:** files written by the previous code are still sitting in `public/avatars` and are still served raw by `express.static`. This code change does not retract them. Move them into `storage/avatars` under generated names, or delete them, as part of deploying the fix - otherwise an already-uploaded `evil.html` stays live.
