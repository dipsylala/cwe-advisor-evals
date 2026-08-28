# CWE-434 (Unrestricted Upload of File with Dangerous Type) - AvatarInStaticRoot.js:23

## Verdict

**True positive - exploitable as reported.** The magic-byte check on lines 16-20 is real and does constrain the file's *content*, but it does not constrain the two things that decide how the file is later served: the **storage location** (inside the `express.static` root) and the **stored filename/extension** (taken verbatim from the client-supplied `req.file.originalname`). The content check is a filter, not the fix.

Three distinct defects converge on the sink:

1. **Attacker chooses the served extension.** `req.file.originalname` is raw multipart request metadata; multer does not verify or sanitise it. An upload whose bytes begin with a valid PNG/JPEG signature but whose declared filename is `payload.html` passes `fileTypeFromFile` and is written as `public/avatars/payload.html`. `express.static` then serves it with `Content-Type: text/html`. A signature check identifies the file's *prefix* only, so a polyglot - valid PNG header, `<script>` payload appended - satisfies every signature test ever written. Result: stored XSS in the application's own origin, reachable at the URL the endpoint helpfully returns.
2. **Path traversal in the storage path.** `path.join(PUBLIC_DIR, 'avatars', req.file.originalname)` normalises `../` segments, so an `originalname` of `../../app.js` escapes the intended directory, and `fs.mkdir(path.dirname(destination), { recursive: true })` will create whatever directories the traversal names. The write is an arbitrary-path file write, constrained only to content that begins with an image signature - enough to clobber a JS file, a config file, or a template. Note that line 28 reports `path.basename(destination)`, so a successful traversal is invisible in the response.
3. **Uploads land in the webroot.** `PUBLIC_DIR` is passed to `express.static()` on line 10, so anything written under it is served directly by the static handler, outside any application logic that could set a safe `Content-Type` or `X-Content-Type-Options`.

Secondary finding: `image/svg+xml` in the `ALLOWED` array is **dead but dangerous intent**. `file-type` detects by magic bytes and has no signature for SVG (it is text, not a binary container), so `fileTypeFromFile` never returns `image/svg+xml` and the entry is currently unreachable. It should not be re-enabled through some other detection path: SVG carries active content and, served inline from the application's origin, executes script there. It is removed in the fix below.

Also noted, not changed (outside this finding): the rejection path on line 19 returns without unlinking `req.file.path`, so rejected uploads accumulate in `/tmp/incoming`.

## Source

**Taint path**

| Step | Location | Value |
|---|---|---|
| Source | `POST /avatar`, multipart `avatar` field | `req.file.originalname` - client-controlled filename; `req.file.path` - temp file at `/tmp/incoming/<random>` |
| Partial gate | lines 15-20 | `fileTypeFromFile(req.file.path)` checks the content signature only. Constrains bytes; does **not** constrain `originalname`, which flows past unchanged |
| Sink (line 23) | `path.join(PUBLIC_DIR, 'avatars', req.file.originalname)` | Tainted filename becomes the storage path, inside the `express.static` root |
| Write (line 26) | `fs.rename(req.file.path, destination)` | Attacker-named file written to an attacker-influenced path |
| Exit (lines 10, 28) | `express.static(PUBLIC_DIR)` | File served back to any client with a `Content-Type` derived from the attacker's extension |

**Vulnerable code**

```js
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');

const app = express();
const upload = multer({ dest: '/tmp/incoming' });   // no limits.fileSize

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));                // everything under PUBLIC_DIR is served directly

const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml'];  // svg unreachable via magic bytes, and active content

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }
  // detected.mime is validated, then discarded - it decides nothing downstream

  // VULNERABLE: client-controlled originalname becomes the storage path, and that path
  // is inside the express.static root. The attacker picks the extension (-> served as
  // text/html) and can escape the directory with ../ segments.
  const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);

  await fs.mkdir(path.dirname(destination), { recursive: true });   // will create traversed directories
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + path.basename(destination) });      // basename hides a successful traversal
});

module.exports = app;
```

**Sink contract, before changing anything**

- *Returns:* `fs.rename` resolves to `undefined`; the handler's observable output is `{ url }`, a path the client is expected to be able to `GET`. The fix must keep a working retrieval URL of that shape.
- *Discards:* `detected.ext` - `file-type` returns the canonical extension alongside the MIME, and the current code throws it away. That discarded value is exactly what the fix needs.
- *Arguments left implicit:* `multer({ dest })` supplies no `fileFilter` and no `limits`, so upload size is unbounded. `path.join` performs no containment check - it normalises `..` rather than rejecting it. `mkdir({ recursive: true })` will create any directory the (traversed) path names.
- *Failure behaviour:* the handler has no `try`/`catch`, and Express 4 does not catch rejected promises from async handlers, so a `rename` failure (for example `EXDEV`, when `/tmp` and the project directory are on different filesystems) surfaces as an unhandled rejection rather than a 500. The fix below does not change this - it is pre-existing and unrelated to the weakness - but the cross-device `rename` caveat still applies to the new destination.

## Fix

**Dependencies.** No version bump is required by this fix. `file-type` is already used correctly: it is ESM-only from v17, and this CommonJS handler already loads it with a dynamic `await import('file-type')`. The guidance carries no minimum-version floor for `file-type` or `multer`, so confirm the resolved versions of both against SCA/dependency-check tooling rather than treating any version stated here as vetted. `crypto` is a Node built-in; `crypto.randomUUID()` requires Node 14.17+ / 16+.

**Fixed code**

```js
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs/promises');

const app = express();

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
const upload = multer({ dest: '/tmp/incoming', limits: { fileSize: MAX_UPLOAD_BYTES } });

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

// Deliberately outside PUBLIC_DIR: express.static must never reach uploaded content.
const AVATAR_DIR = path.join(__dirname, 'storage', 'avatars');

// Detected MIME -> stored extension. The stored extension comes from this map only.
const ALLOWED = new Map([
  ['image/png', 'png'],
  ['image/jpeg', 'jpg'],
]);

const STORED_NAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(png|jpg)$/;

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  const ext = detected && ALLOWED.get(detected.mime);
  if (!ext) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // Storage identity is server-generated end to end: random stem, extension from the
  // allowlist entry that matched. req.file.originalname is never used as a path component.
  const storedName = `${crypto.randomUUID()}.${ext}`;
  const destination = path.join(AVATAR_DIR, storedName);

  await fs.mkdir(AVATAR_DIR, { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + storedName });
});

// Uploads are served by the application, not by express.static, so the response headers are
// chosen here rather than inferred from an attacker-chosen extension.
app.get('/avatars/:name', (req, res) => {
  const { name } = req.params;
  if (!STORED_NAME.test(name)) {
    return res.status(404).end();
  }

  res.sendFile(path.join(AVATAR_DIR, name), {
    headers: {
      'Content-Type': name.endsWith('.png') ? 'image/png' : 'image/jpeg',
      'Content-Disposition': 'inline',
      'X-Content-Type-Options': 'nosniff',
    },
  });
});

module.exports = app;
```

## Explanation

The change breaks taint at the allowlist rather than merely testing at it. `ALLOWED` becomes a `mime -> ext` map, so a successful check now yields a trusted canonical value (`ext`) that is used downstream, instead of a boolean that lets the original client-supplied name continue to the sink. The storage path is assembled entirely from server-controlled parts - a `crypto.randomUUID()` stem plus the allowlist's extension - so `req.file.originalname` never reaches a filesystem path. That closes both the extension-choice defect (a PNG-prefixed polyglot can no longer land as `.html`) and the traversal defect (a UUID contains no `..` and no separators, so `path.join` has nothing to normalise, and `mkdir` now targets a constant directory). `AVATAR_DIR` moves outside `PUBLIC_DIR`, so `express.static` cannot serve uploaded bytes at all; a dedicated route re-establishes the `/avatars/<name>` URL that the endpoint's JSON response promises, re-validates the name against the generated-name pattern before touching the filesystem, and sets `Content-Type` from the stored extension along with `X-Content-Type-Options: nosniff` so the browser cannot sniff a polyglot into an executable type. `Content-Disposition: inline` is used rather than forcing an attachment because avatars are meant to render in an `<img>`; that is safe here precisely because only PNG and JPEG can be stored and the type is now asserted by the server.

Two changes are hardening rather than the core fix, and are named as such. `limits: { fileSize }` bounds the upload before it consumes disk - size limits are a required secondary control for this weakness, and their absence was part of the same unrestricted-upload finding; exceeding the limit produces a `MulterError` handled by Express's default error handler. Dropping `image/svg+xml` removes an entry that `file-type` could never have returned and that would have been genuinely dangerous had it been reachable by any other detection path.

Everything else is deliberately unchanged: the rejection status and body, the response shape, the `rename`-based move, and the handler's (absent) error handling. Two residual items belong in separate work rather than folded into this fix. First, a signature check validates a prefix, so a polyglot's trailing payload still sits in the stored bytes; it is inert now because the file can only ever be served as `image/png` or `image/jpeg`, but decoding and re-encoding each image on upload (with `sharp`, for example) is what actually strips it - worth adding if these images are ever reprocessed or served by another system. Second, any files already written under `public/avatars/` by the vulnerable code remain in the static root and are still served by `express.static`; audit and clear that directory as part of deploying this change.

Verification: confirm rejection of a file whose `originalname` ends in `.html`, `.svg`, or `.php` regardless of its content; confirm a file named `../../app.js` with a valid PNG body is stored as a UUID under `storage/avatars` and writes nothing outside it; confirm an over-limit upload is rejected; confirm the returned URL renders in an `<img>`; and confirm a request to `/avatars/../../app.js` returns 404.
