## Verdict

Confirmed. The `/avatar` handler validates the uploaded file's content by sniffing magic bytes, but the allowlist itself includes `image/svg+xml`, and the file is then written into a statically-served directory under a name taken directly from `req.file.originalname` (the extension) rather than from the validated content type. An SVG is a dangerous type to accept here: browsers execute `<script>` and event-handler attributes inside SVG documents, so a validated, "allowed" upload can still deliver stored XSS once it is served from the app's own origin. Decoupling the stored file's extension from the detected type also means the extension is fully attacker-controlled independent of what was actually validated.

## Source

`req.file.originalname` (the client-supplied upload filename, used for the extension of the file written into the public static root) — `AvatarInStaticRoot.js:23`.

## Fix

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

// SVG is intentionally excluded: it can carry <script> and event-handler
// content, and this app serves uploads from its own static origin, so
// accepting SVG here would allow stored XSS via a "validated" image upload.
const ALLOWED_EXT_BY_MIME = new Map([
  ['image/png', '.png'],
  ['image/jpeg', '.jpg'],
]);

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  const ext = detected && ALLOWED_EXT_BY_MIME.get(detected.mime);
  if (!ext) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // Derive the stored filename entirely from server-controlled data: a
  // random identifier plus the extension mapped from the *detected* type.
  // req.file.originalname is never used to build a filesystem path, which
  // also removes the path-traversal exposure of joining raw user input
  // into a path under the static root.
  const safeName = `${crypto.randomUUID()}${ext}`;
  const destination = path.join(PUBLIC_DIR, 'avatars', safeName);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + safeName });
});

module.exports = app;
```

## Explanation

Two changes close the finding:

1. **Dangerous type removed from the allowlist.** `image/svg+xml` is dropped from the set of accepted content types. SVG is XML that can embed `<script>` elements and `on*` event-handler attributes; a browser that opens an uploaded SVG directly (which is exactly what happens here, since `avatars/` sits under `express.static(PUBLIC_DIR)`) will execute that script in the app's origin. Magic-byte sniffing with `file-type` correctly confirms a file *is* a well-formed SVG, but "well-formed SVG" and "safe to serve as a static same-origin resource" are different properties — sniffing alone can't establish the second one. If SVG support is a hard requirement, it needs to go through a dedicated sanitizer (e.g. stripping scripts/handlers with a maintained library) before being written to the static root, or be served from a separate, script-inert origin/Content-Disposition rather than inline.

2. **Stored filename decoupled from user input.** The original code took the file *content* from validated bytes but the file's *extension* from `req.file.originalname`, an attacker-controlled string with no relationship to what was actually validated — so the on-disk/served file extension was effectively unrestricted regardless of the MIME check. The fix builds the destination name entirely from trusted values: a random UUID for the base name and an extension selected from a fixed map keyed by the *detected* MIME type. This also incidentally removes any path-traversal exposure from joining a raw client-supplied string into a filesystem path, since no part of `originalname` reaches `path.join` anymore.
