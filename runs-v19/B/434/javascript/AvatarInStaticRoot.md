## Verdict

Exploitable. The vulnerability is confirmed real and the fix closes it.

## Source

The attacker-controlled `req.file.originalname` parameter, supplied by the client in the multipart request headers, is used directly at line 23 to construct the storage path without sanitization or validation. This parameter allows an attacker to specify the filename written to disk.

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
const PRIVATE_DIR = path.join(__dirname, 'private_avatars');

app.use(express.static(PUBLIC_DIR));

const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml'];

// Serve avatar files from private directory
app.get('/avatars/:filename', (req, res) => {
  const filename = path.basename(req.params.filename);
  const filepath = path.join(PRIVATE_DIR, filename);
  res.sendFile(filepath);
});

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // FIXED: Generate a random filename using detected extension, not client-supplied name
  const filename = crypto.randomUUID() + '.' + detected.ext;
  const destination = path.join(PRIVATE_DIR, filename);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + filename });
});

module.exports = app;
```

## Explanation

The original code validated the file's MIME type against an allowlist but used the client-supplied original filename directly as the storage path. This introduced three attack vectors: (1) path traversal via sequences like `../` to write files outside the intended directory, (2) arbitrary file extensions that could trigger unintended handlers if files were misserved, and (3) since files were stored within the webroot served by `express.static()`, uploaded files with executable extensions could be directly executed by the server if misconfigured. The fix addresses all three by generating a random UUID-based filename with the extension derived from the detected file type (not the original name), storing files in a private directory outside the static root, and serving them through a controlled route via `res.sendFile()` that prevents direct execution access. This breaks the taint chain: the attacker-controlled `originalname` is never used for storage or serving decisions; instead, the server-controlled detected MIME type determines both the extension and the storage location.

## Behaviour changes

1. **Filename generation**: Files are now stored as random UUIDs with detected extensions (e.g., `f47ac10b-58cc-4372-a567-0e02b2c3d479.png`) instead of using client-supplied original filenames. This is a security fix with no functional regression; the client never needs to know or control the storage filename.

2. **Storage location**: Files are now stored in `private_avatars/` directory (outside the express.static root) instead of `public/avatars/`. This requires the `private_avatars/` directory to be created in the deployment environment but prevents direct execution of uploaded files through the static server.

3. **Serving mechanism**: A new GET `/avatars/:filename` route handles file delivery using `res.sendFile()`, replacing direct static serving. This is required by the new storage location and provides better control over response headers and error handling. The URL structure and format remain unchanged to the client.

4. **Extension source**: File extensions now come from `detected.ext` (the detected MIME type) instead of the original filename, ensuring the extension accurately represents the file's actual content type rather than any client-supplied value.

5. **No changes to**:
   - File type validation logic (still uses `file-type` library and ALLOWED allowlist)
   - Multipart upload handling (still uses multer with default configuration)
   - Response format (still returns `{ url: '/avatars/...' }`)
   - Request authentication/authorization (not added; remains as baseline)

Verification: Node.js syntax check passed with no errors.
