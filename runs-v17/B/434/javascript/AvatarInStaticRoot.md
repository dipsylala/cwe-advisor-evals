## Verdict

Confirmed. Line 23 uses `req.file.originalname` (client-supplied, untrusted) directly as the storage filename without sanitization, and stores the result inside `PUBLIC_DIR` which is served by `express.static()`. This allows path traversal (e.g. `../../../etc/passwd`) and storage of files within the webroot, violating CWE-434 even though file-type validation is present.

## Source

The vulnerability originates from `req.file.originalname`, which is a multipart header value supplied by the HTTP client and not verified by multer itself. This value flows into the file storage path at line 23.

Data flow:
- Line 14: Multer receives upload into `/tmp/incoming`
- Line 16: Magic bytes validated against allowlist
- Line 23: **Vulnerable sink** - `req.file.originalname` used in path without sanitization
- Line 10: `PUBLIC_DIR` served by `express.static()` makes storage location exploitable

## Fix

### File: AvatarInStaticRoot.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const { randomUUID } = require('crypto');

const app = express();
const upload = multer({ dest: '/tmp/incoming' });

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

// Private storage directory, outside webroot
const UPLOAD_DIR = path.join(__dirname, '.uploaded');
const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml'];

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // Generate random filename using detected type's extension, not client-supplied name
  const filename = `${randomUUID()}.${detected.ext}`;
  const destination = path.join(UPLOAD_DIR, filename);

  await fs.mkdir(UPLOAD_DIR, { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatar-file/' + filename });
});

// Serve uploaded files through application-controlled route, not express.static
app.get('/avatar-file/:filename', async (req, res) => {
  const { filename } = req.params;
  
  // Reject path traversal attempts
  if (filename.includes('..') || filename.includes('/')) {
    return res.status(400).json({ error: 'invalid filename' });
  }
  
  const filepath = path.join(UPLOAD_DIR, filename);
  
  // Verify file exists and is within UPLOAD_DIR (defense-in-depth)
  try {
    const realpath = await fs.realpath(filepath);
    const uploadDirReal = await fs.realpath(UPLOAD_DIR);
    if (!realpath.startsWith(uploadDirReal)) {
      return res.status(404).json({ error: 'file not found' });
    }
  } catch {
    return res.status(404).json({ error: 'file not found' });
  }
  
  res.download(filepath);
});

module.exports = app;
```

## Explanation

The fix addresses CWE-434 through three key changes:

1. **Random filename generation**: Replaces `req.file.originalname` with `randomUUID()`, eliminating both the path-traversal risk and the attacker's ability to specify the storage location. The filename is now server-controlled and unpredictable.

2. **Extension from detected type**: Uses `detected.ext` (from file-type's magic-byte analysis) instead of trusting the client-supplied extension. This ensures the extension always matches the validated content, preventing polyglot or mismatched-type attacks.

3. **Storage outside webroot**: Stores the file in a private `.uploaded` directory outside `PUBLIC_DIR` instead of inside the served static root. Files are no longer executable by the web server when accessed through the filesystem; they must go through an application route.

4. **Controlled serving route**: Added `/avatar-file/` endpoint that validates the filename, checks for path traversal, and verifies the file is within the private directory (defense-in-depth with `realpath` normalization). This replaces direct `express.static` serving and enforces application-level access control.

The file-type validation at line 18 was already correct; this fix complements it by ensuring the filename, extension, and storage location cannot be exploited by the attacker.

## Behaviour changes

**Before**: Client uploads `shell.php.png` with PNG magic bytes. Magic check passes, file stored as `/public/avatars/shell.php.png`, served by express.static. Attacker accesses via `/avatars/shell.php.png` and PHP processes it as `.php`.

**After**: Same upload generates filename `a1b2c3d4-e5f6-47g8-h9i0-j1k2l3m4n5o6.png` (extension from detected type, not client), stored in `/.uploaded/`, accessible only via `/avatar-file/a1b2c3d4-e5f6-47g8-h9i0-j1k2l3m4n5o6.png` route which serves it as attachment, never executes it. Path traversal attempts like `../../../etc/passwd` rejected at the route layer.

The response URL changes from `/avatars/{original-filename}` to `/avatar-file/{random-uuid}.{detected-ext}`, which is a breaking change for clients but necessary to eliminate the vulnerability.
