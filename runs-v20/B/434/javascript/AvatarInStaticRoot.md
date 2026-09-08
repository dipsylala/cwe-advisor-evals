## Verdict

Exploitable (confidence: high). CWE-434, Unrestricted Upload of File with Dangerous Type, confirmed at the reported sink (line 23 of `AvatarInStaticRoot.js`).

## Source

`req.file.originalname` - the client-supplied filename from the `multipart/form-data` upload handled by `multer`. It is attacker-controlled and is not verified by `multer` or by the magic-byte check that runs earlier in the handler.

Data flow: `upload.single('avatar')` populates `req.file` (`path` = temp file on disk, `originalname` = client-supplied name) -> `fileTypeFromFile(req.file.path)` inspects the actual bytes and gates on `ALLOWED` mime types (this part is sound) -> the reported line builds `destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname)`, reusing the untrusted `originalname` for both the stored filename and its extension -> `fs.rename` places the file at that path -> `PUBLIC_DIR` is mounted with `app.use(express.static(PUBLIC_DIR))`, so the file becomes immediately and directly web-servable at `/avatars/<originalname>`.

Sink contract before the fix: `fs.rename` returns a promise resolving to `undefined` on success and rejecting on error (unhandled here, propagating to the route's async rejection); `fs.mkdir(..., { recursive: true })` silently no-ops if the directory already exists; the response returns only `{ url }`, discarding nothing else. The two problems are (1) the destination directory is inside the `express.static` webroot, so any file that clears the magic-byte check is served back to any visitor exactly as stored, and (2) the stored *extension* is taken from `originalname` rather than from the verified `detected` result, so content that sniffs as one allowed type (e.g. `image/svg+xml`, which can carry an inline `<script>`) can be saved and served under whatever extension the attacker chose, independent of the byte-level check that was just performed.

## Fix

### File: AvatarInStaticRoot.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

const app = express();
const upload = multer({ dest: '/tmp/incoming' });

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml'];

// Stored outside PUBLIC_DIR: express.static(PUBLIC_DIR) above must never be able
// to serve an uploaded file directly.
const AVATAR_DIR = path.join(__dirname, 'private-avatars');

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // Generated name + detected extension - never the client-supplied originalname.
  const filename = `${crypto.randomUUID()}.${detected.ext}`;
  const destination = path.join(AVATAR_DIR, filename);

  await fs.mkdir(AVATAR_DIR, { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + filename });
});

// Serves stored avatars through application logic instead of express.static.
// :filename is only ever a value this app generated above (crypto.randomUUID()
// plus the detected extension), and is still re-validated against that exact
// shape before touching the filesystem.
const AVATAR_FILENAME_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z0-9]+$/i;

app.get('/avatars/:filename', (req, res) => {
  const { filename } = req.params;
  if (!AVATAR_FILENAME_RE.test(filename)) {
    return res.status(404).end();
  }
  res.sendFile(path.join(AVATAR_DIR, filename));
});

module.exports = app;
```

## Explanation

The magic-byte check against `ALLOWED` was already correct and is unchanged. The fix addresses the two remaining gaps: storage location and filename/extension provenance. Uploaded files now land in `AVATAR_DIR` (`private-avatars`), a directory never passed to `express.static`, so a file can no longer be fetched by guessing or being told its name unless the application's own route serves it. The stored filename is generated with `crypto.randomUUID()` and its extension is taken from `detected.ext` - the value `file-type` derived from the verified content - rather than from `req.file.originalname`, so the extension the file is eventually served under always matches the type that was actually checked. A new `GET /avatars/:filename` route replaces static serving; it re-validates the filename against the exact `<uuid>.<ext>` shape produced above before calling `res.sendFile()`, so even though the value only ever originates from this app's own generation, the sink still never receives an unvalidated path segment.

## Behaviour changes

- Response `url` field now returns a generated filename (`<uuid>.<ext>`) instead of echoing the client's original filename. Any caller relying on the returned URL preserving the uploaded file's original name will see a different name; the file's bytes and detected type are unaffected.
- Avatars are now served via an explicit `GET /avatars/:filename` route (`res.sendFile`) rather than directly through `express.static`. Response bytes and content-type resolution for a given extension are the same; the change is that the response is now gated by the filename-shape check above rather than by whatever `express.static` would serve from the public root.
- Storage directory moved from `PUBLIC_DIR/avatars` to a sibling `private-avatars` directory outside the static root - required to close the finding, since any path under `PUBLIC_DIR` is directly web-servable.
- Extension used for the stored file now comes from `detected.ext` (the verified content type) instead of `req.file.originalname`'s extension. An upload whose content matches an allowed type but whose original filename carried a different or missing extension will now be stored with the extension matching its real, verified type instead of the client-chosen one.
- Verification: `node --check` on the fixed file passed (syntax only; no test runner or `file-type`/`express`/`multer` install was available in this environment to execute the route).
- Assumptions: `detected.ext` (returned by `file-type` alongside `detected.mime`) is used directly per the loaded JavaScript guidance rather than introducing a separate mime-to-extension map, keeping the set of accepted content types identical to the original code's `ALLOWED` list. The `file-type` package, `crypto.randomUUID()`, and `res.sendFile()` are all referenced by the loaded guidance or Node/Express standard APIs; none are newly introduced without a source.
