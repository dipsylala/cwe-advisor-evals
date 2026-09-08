## Verdict

Confirmed. The upload handler validates the uploaded bytes' magic-number MIME type but then persists the file under a name and extension taken directly from the client-supplied `multipart/form-data` filename, inside a directory that is served statically. That lets an attacker control both the on-disk path (traversal) and the served file extension (dangerous type), independent of the content check.

## Source

`req.file.originalname` — the client-supplied filename field from the `multipart/form-data` upload (populated by `multer`) — is untrusted input. It flows unmodified into `path.join(PUBLIC_DIR, 'avatars', req.file.originalname)` at line 23, and the resulting path is used as the destination of `fs.rename()`, placing the attacker-named file inside `PUBLIC_DIR`, which is mounted at the application root via `express.static(PUBLIC_DIR)`.

Two independent problems follow from that:

- `originalname` can contain path segments (e.g. `../../something`), letting `path.join` resolve outside `avatars/` or even outside `PUBLIC_DIR`.
- The file's on-disk extension is whatever the attacker put in `originalname`, regardless of the verified content type. `express.static` sets the response `Content-Type` from the file extension, so an attacker can upload a file whose bytes pass the `file-type` allowlist check yet is stored with — and later served as — an extension of their choosing, and can additionally rely on `image/svg+xml` (an XML format that can carry an executable `<script>` element) being on the accepted-content allowlist.

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

// SVG is deliberately not accepted here: it is an XML format that can carry
// an embedded <script> element, so a file that passes a magic-byte content
// check can still execute script when a browser opens it directly from the
// static root. Only raster formats with no script capability are mapped.
const EXTENSION_BY_MIME = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
};

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  const extension = detected && EXTENSION_BY_MIME[detected.mime];
  if (!extension) {
    await fs.unlink(req.file.path).catch(() => {});
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // The stored filename is generated server-side from the verified content
  // type. req.file.originalname (client-controlled) is never used to build
  // a filesystem path, which also removes the path traversal exposure that
  // came from joining it into PUBLIC_DIR.
  const filename = `${crypto.randomUUID()}${extension}`;
  const destination = path.join(PUBLIC_DIR, 'avatars', filename);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + filename });
});

module.exports = app;
```

## Explanation

The fix removes `req.file.originalname` from the path-construction logic entirely rather than trying to sanitize it, because the value is both the traversal vector and the extension-spoofing vector:

- **Destination path**: the stored filename is now `crypto.randomUUID()` plus a fixed extension chosen server-side, so the destination passed to `fs.rename()` never contains attacker-supplied path segments. There is no `../` to strip because no part of the filename comes from the client.
- **Dangerous extension**: the extension written to disk (and therefore the extension `express.static` uses to pick the response `Content-Type` when the avatar is later requested) is looked up from a fixed map keyed by the MIME type that `file-type` already detected from the file's magic bytes. An attacker can no longer decouple "what the bytes are" from "what extension it's served as" — the two are now the same fact.
- **Dropping SVG**: `image/svg+xml` is removed from the accepted set. SVG's magic bytes are easy to produce, but the format itself is script-capable, so passing the content check did not make it safe to serve back from the same origin as the application. The other two accepted types (PNG, JPEG) have no script execution surface, so no additional sanitization step is needed for them.
- The temporary upload is now removed (`fs.unlink`) when the type check fails, so a rejected upload doesn't leave attacker-supplied content sitting in the temp directory.

The response still reports the same `/avatars/<name>` URL shape the client expects; only the value of `<name>` changed from attacker-chosen to server-generated.
