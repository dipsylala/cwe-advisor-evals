## Verdict

Confirmed. The code validates file content by magic bytes against a MIME allowlist, but then stores the file using the client-supplied original filename in a directory served by `express.static()`. This violates two core principles: the extension must be derived from the detected type (not the client's filename), and uploaded files must not be stored in a path served directly to clients. The allowlist includes `image/svg+xml`, which can carry script content; SVG files require re-encoding or must be removed from the allowlist.

## Source

`req.file.originalname` at line 23 of AvatarInStaticRoot.js. The client-supplied filename from the multipart request is passed directly to `path.join()` for storage destination without deriving the extension from the detected file type.

## Fix

**Primary issues to address:**

1. Remove `image/svg+xml` from the ALLOWED list or enforce SVG sanitization (CWE-434 remediation prefers removal).
2. Generate a random filename for storage using `crypto.randomUUID()`.
3. Derive the extension from `detected.ext` (returned by `fileTypeFromFile`), not from `req.file.originalname`.
4. Store the file outside the static root, or serve it through an application-controlled route that sets appropriate headers (`Content-Disposition: attachment`).

**Fixed code (option: store outside static root and serve through a route):**

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

// Private directory for uploaded files, outside any express.static root
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Allowlist: only safe image formats; SVG removed due to script execution risk
const ALLOWED = ['image/png', 'image/jpeg'];

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    await fs.unlink(req.file.path); // Clean up rejected upload
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // Generate random filename; extension from detected type, not client input
  const storageName = `${crypto.randomUUID()}.${detected.ext}`;
  const destination = path.join(UPLOAD_DIR, storageName);

  await fs.mkdir(UPLOAD_DIR, { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: `/avatar/${storageName}` });
});

// Serve uploaded avatars through a controlled route with safe headers
app.get('/avatar/:filename', async (req, res) => {
  const filename = path.basename(req.params.filename);
  const filepath = path.join(UPLOAD_DIR, filename);
  
  // Validate the file exists and is within UPLOAD_DIR to prevent traversal
  try {
    const realpath = await fs.realpath(filepath);
    if (!realpath.startsWith(await fs.realpath(UPLOAD_DIR))) {
      return res.status(404).json({ error: 'not found' });
    }
    res.set('Content-Disposition', 'attachment');
    res.set('X-Content-Type-Options', 'nosniff');
    res.sendFile(filepath);
  } catch {
    res.status(404).json({ error: 'not found' });
  }
});

module.exports = app;
```

**Minimum-scope fix (if moving files outside static root is not feasible):**

If storage must remain in the static root, at minimum:

1. Remove `image/svg+xml` from ALLOWED.
2. Replace line 23 with: `const destination = path.join(PUBLIC_DIR, 'avatars', `${crypto.randomUUID()}.${detected.ext}`);`
3. Update line 28 to use the generated filename, not `path.basename(destination)`.

## Explanation

The vulnerability is that `req.file.originalname` is attacker-controlled request metadata and carries two separate risks:

1. **Extension control**: The filename's extension determines how a file is served. By controlling the extension (e.g., uploading `shell.php` and including a PHP MIME type in the multipart header), an attacker can trick the server or browser into interpreting the uploaded file as executable code, even if the actual file bytes are validated. The fix extracts the extension from the detected MIME type through `detected.ext`, ensuring the extension matches the actual content.

2. **Storage location**: Files stored in `PUBLIC_DIR` (which is served by `express.static()`) are directly accessible at predictable URLs. When an uploaded file reaches a client's browser through this path, execution depends on the MIME type the server sends and the file's extension. A script-bearing SVG file accessed as `.svg` will execute in the browser; moving uploads to a non-static directory and serving them through a controlled route allows the application to enforce safe headers (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`) that prevent interpretation as active content.

3. **SVG risk**: `image/svg+xml` is inherently dangerous because SVG files are XML documents that can contain `<script>` tags. No amount of re-encoding without full re-serialization (stripping and re-building the SVG from approved elements) can safely allow SVG uploads. The fix removes SVG from the allowlist.

The fix validates content by magic bytes (which is already done correctly), then breaks the taint by using only the detected type and a generated name for storage and serving decisions, never the client-supplied original filename or MIME type again.

## Behaviour changes

- Uploaded files are no longer accessible at a predictable path derived from the original filename. A file uploaded as `shell.php` no longer appears at `/avatars/shell.php`.
- File storage moves outside the web-served directory, preventing direct HTTP access and interpretation of uploaded content as executable code by the web server.
- Uploaded files are served with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, instructing browsers to treat them as downloads rather than inline content and to ignore any MIME-type guessing based on file extension.
- SVG files are no longer accepted, eliminating the vector for embedded script execution.
- The URL returned to the client changes from `/avatars/{originalname}` to `/avatar/{randomUUID}.{ext}`, which is both safer and non-predictable.
