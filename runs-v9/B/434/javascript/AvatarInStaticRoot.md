## Verdict

- **cwe_id**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **location**: `AvatarInStaticRoot.js`, line 23 (`path.join(PUBLIC_DIR, 'avatars', req.file.originalname)`)
- **verdict**: exploitable
- **confidence**: high

## Source

- **Source**: `req.file.originalname`, the client-supplied filename from the multipart upload handled by `multer` (line 14, `upload.single('avatar')`). Multer does not verify this value; it is attacker-controlled request metadata.
- **Sink**: `path.join(PUBLIC_DIR, 'avatars', req.file.originalname)` (line 23) followed by `fs.rename(req.file.path, destination)` (line 26), which writes the uploaded file into `avatars/` under `PUBLIC_DIR` — the directory mounted with `express.static(PUBLIC_DIR)` at line 10 and therefore served directly to any requester.
- **Flow**: the handler does check the file's real bytes with `fileTypeFromFile` and reject anything outside `ALLOWED` (lines 15-20), so the magic-byte gate itself is sound. But the *storage name and extension* used at the sink come straight from `req.file.originalname`, not from the verified `detected` result, and the file lands inside the statically-served webroot. Two consequences follow: (1) `image/svg+xml` is in `ALLOWED`, and a well-formed SVG can carry an inline `<script>`; once such a file is written under `PUBLIC_DIR/avatars` with the attacker's own `.svg` name, `express.static` serves it back with `Content-Type: image/svg+xml`, and a browser that navigates to it renders the SVG and runs the embedded script in the site's origin — a stored-XSS/dangerous-type upload despite the content check having "passed". (2) because the stored extension is taken from `originalname` rather than `detected.mime`, the extension `express.static` uses to pick the response `Content-Type` is decoupled from the byte-verified type, so validated content and served type can disagree. Both are the CWE-434 pattern this finding flags: content-type validation happened, but the file is still persisted at an attacker-chosen name/extension inside a directly-executable/servable location.

## Fix

No new third-party library is required — `file-type` is already in use for the content check; `crypto` is a Node built-in.

**Vulnerable code:**

```javascript
app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
  const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + path.basename(destination) });
});
```

**Fixed code:**

```javascript
const crypto = require('crypto');

// Storage lives outside PUBLIC_DIR, so it is never reachable through express.static.
const AVATAR_DIR = path.join(__dirname, 'private-avatars');

// Extension is derived from the verified content type, never from the client's filename.
const EXT_BY_MIME = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/svg+xml': 'svg',
};

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  const ext = EXT_BY_MIME[detected.mime];
  const filename = `${crypto.randomUUID()}.${ext}`;
  const destination = path.join(AVATAR_DIR, filename);

  await fs.mkdir(AVATAR_DIR, { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + filename });
});

// Files are served through application logic instead of express.static, using the
// verified mime type for Content-Type rather than trusting a stored extension.
app.get('/avatars/:filename', async (req, res) => {
  const filename = path.basename(req.params.filename);
  const ext = path.extname(filename).slice(1);
  const mime = Object.keys(EXT_BY_MIME).find((m) => EXT_BY_MIME[m] === ext);

  if (!mime) {
    return res.status(404).end();
  }

  res.set('Content-Type', mime);
  res.set('X-Content-Type-Options', 'nosniff');
  res.sendFile(path.join(AVATAR_DIR, filename), (err) => {
    if (err) res.status(404).end();
  });
});
```

## Explanation

The fix moves avatar storage out of `PUBLIC_DIR` into a private directory (`AVATAR_DIR`) that is never mounted with `express.static`, so an uploaded file can no longer be reached by simply guessing or requesting its static path. It also stops using `req.file.originalname` for the stored filename and extension: the filename is now a `crypto.randomUUID()` value, and the extension is looked up from the already-verified `detected.mime` through a fixed `EXT_BY_MIME` allowlist map, so the stored suffix always matches the byte-verified type instead of an attacker-chosen one. Because the file no longer sits under a statically-served directory, it can only be retrieved through the new `/avatars/:filename` route, which re-derives the response `Content-Type` from the same verified-mime allowlist and sets `X-Content-Type-Options: nosniff`, so the type used to serve the file is always the one that was actually validated, not one inferred from a client-supplied name. The existing magic-byte check via `file-type` against `ALLOWED` is unchanged and continues to gate content before any of this runs.

## Behaviour changes

- The success response's `url` field now points at `/avatars/<uuid>.<ext>` served by the new dedicated route, instead of `/avatars/<original-filename>` served by `express.static`. This is required by the fix: storage moved outside the static webroot, so a new serving route is the only way to hand the file back. Callers that relied on the original client-supplied filename appearing in the URL will see a generated name instead.
- Files served through the new `/avatars/:filename` route lose the caching/conditional-GET behaviour `express.static` provided automatically (`ETag`, `Last-Modified`, `Cache-Control`, `Range` support via `express.static`'s defaults). `res.sendFile` supports some of this but is not configured identically here; a production deployment may want to add explicit cache headers to the new route to match prior performance characteristics.
- The response now always carries `X-Content-Type-Options: nosniff` on avatar responses, which it did not before (previously relied on `express.static`'s default headers). This is an intentional secondary control from the guidance and does not change how the image renders in an `<img>` tag.
- The uploads directory is created lazily on first request (`fs.mkdir(AVATAR_DIR, ...)`) exactly as the original code did for its target directory — no change in that respect, aside from the directory itself now being outside `PUBLIC_DIR`.

## Assumptions

- Assumed avatars are meant to be displayed inline (e.g. in `<img>` tags), so the new serving route sets the verified image `Content-Type` directly rather than forcing `Content-Disposition: attachment`; forcing a download would close the SVG-script-execution risk further but would also break normal inline avatar rendering, so it was left out as out of scope for a surgical fix to the reported sink. If inline SVG rendering from user content is not acceptable for this application, removing `image/svg+xml` from `ALLOWED` (or sanitizing/re-encoding SVGs before storage) is a follow-up worth considering, but that changes the accepted-type policy rather than the storage/serving flaw reported here, so it was not made automatically.
