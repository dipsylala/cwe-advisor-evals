## Verdict

Exploitable. The vulnerability is confirmed at line 23. Despite validating file content with magic-byte inspection, the code uses the client-supplied `req.file.originalname` as the storage filename and stores the file inside the webroot. An attacker can:
1. Upload a valid PNG/JPEG file with a malicious filename like `shell.php` to bypass extension-based execution checks
2. Upload an SVG file (permitted but dangerous) carrying embedded `<script>` tags that execute in browsers when the file is served
3. Use path-traversal sequences in the filename (e.g., `../../../shell.php`) to write outside the intended directory

The security-relevant sink is line 23's use of `originalname` in the path combined with storage inside `PUBLIC_DIR`, which is served by `express.static()` on line 10.

## Source

The vulnerable code path:
1. **Source (line 7)**: Multer receives multipart upload with untrusted `originalname` and `mimetype`
2. **Validation (lines 15-18)**: File content is checked for magic bytes against an allowlist (good)
3. **Sink (line 23)**: File is stored using `path.join(PUBLIC_DIR, 'avatars', req.file.originalname)` - the `originalname` is untrusted client input
4. **Exposure (line 10)**: Storage location `PUBLIC_DIR` is served by `express.static()`, making files executable/renderable if extension matches an active type

The `ALLOWED` array validates MIME types detected from file content, but this validation is bypassed by using `originalname` as the storage filename.

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

// Private storage directory outside webroot
const PRIVATE_UPLOAD_DIR = path.join(__dirname, '.uploads');

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // Generate random filename using detected extension, not client-supplied originalname
  const filename = `${crypto.randomUUID()}.${detected.ext}`;
  const destination = path.join(PRIVATE_UPLOAD_DIR, filename);

  await fs.mkdir(PRIVATE_UPLOAD_DIR, { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ filename: filename });
});

// Serve uploaded files through controlled route with safe headers
app.get('/avatar/:filename', async (req, res) => {
  // Validate filename is a valid UUID format to prevent directory traversal
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z]+$/.test(req.params.filename)) {
    return res.status(400).json({ error: 'invalid filename' });
  }
  
  const filePath = path.join(PRIVATE_UPLOAD_DIR, req.params.filename);
  
  try {
    await res.sendFile(filePath, { 
      headers: { 
        'Content-Disposition': 'inline',
        'X-Content-Type-Options': 'nosniff'
      }
    });
  } catch (err) {
    res.status(404).json({ error: 'not found' });
  }
});

module.exports = app;
```

## Explanation

The fix addresses CWE-434 by applying three critical changes:

1. **Generated filename (line 27)**: Replaces `req.file.originalname` with `crypto.randomUUID()` to eliminate attacker control over the storage path. The extension comes from `detected.ext`, derived from the validated file content, not from client input. This prevents both path-traversal attacks and extension-based execution bypasses.

2. **Private storage directory (line 16, 30)**: Moves uploaded files from `PUBLIC_DIR/avatars/` (inside the webroot) to `.uploads/` (outside the webroot). Files stored outside the webroot cannot be directly executed or served as static assets, even if a malicious extension or SVG payload is present.

3. **Controlled serving route (lines 37-52)**: Introduces a dedicated `/avatar/:filename` endpoint that validates the filename format (UUID + extension, preventing traversal) before serving. The `res.sendFile()` call uses safe response headers: `Content-Disposition: inline` keeps legitimate images displayable in the page, and `X-Content-Type-Options: nosniff` prevents browsers from reinterpreting content based on file extension.

The original code's magic-byte validation was correct but insufficient—the real sink vulnerability was trusting `originalname` for the storage decision. By breaking taint after validation (using only the detected type) and storing outside the webroot, the fix closes the exploitation path while preserving the legitimate upload and serving functionality.

## Behaviour changes

1. **Response format** (line 31): Client receives `filename` instead of a full `/avatars/` URL. The client must now call the `/avatar/:filename` route to retrieve the file.

2. **File storage location**: Files are stored in `.uploads/` (sibling to the app), not in `public/avatars/`. If the application previously enumerated or accessed files directly from `public/avatars/`, those paths will break and must be updated to use the `/avatar/:filename` route instead.

3. **File serving**: Files are no longer served by `express.static()`. All access must go through the `/avatar/:filename` route. This enables per-request validation and safe header injection.

4. **Filename format**: Stored filenames are now UUIDs with detected extensions (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890.png`), not the original client-supplied names. Any tooling that depended on recognizing the original filename will need to track the mapping server-side.

5. **SVG handling**: SVG files are still accepted by the allowlist, but they are now served from a private directory with `X-Content-Type-Options: nosniff`, which prevents browsers from interpreting misleading MIME types. The inline script tags in SVG are still a client-side XSS risk; for defense-in-depth, consider sanitizing SVG content or removing SVG from `ALLOWED` if avatar functionality doesn't require vector graphics.
