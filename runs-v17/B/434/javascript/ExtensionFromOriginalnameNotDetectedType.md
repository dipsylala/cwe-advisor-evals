## Verdict

Exploitable. The code validates file content by detecting MIME type with `file-type`, but stores the file with the client-supplied extension from `req.file.originalname`. An attacker can upload a PNG file (which passes the mime type check) with a malicious `.exe`, `.php`, or `.jsp` extension, allowing code execution if the storage location is later accessed via a web server or script interpreter that respects file extensions.

## Source

`req.file.originalname` - the client-supplied filename in the multipart upload request.

## Fix

### File: ExtensionFromOriginalnameNotDetectedType.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs/promises');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, 'private-uploads');

const ALLOWED_MIME_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'application/pdf',
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

router.post('/documents', upload.single('document'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // file-type is ESM-only from v17, so this CommonJS handler loads it dynamically.
  const { fileTypeFromBuffer } = await import('file-type');
  const detected = await fileTypeFromBuffer(req.file.buffer);

  if (!detected || !ALLOWED_MIME_TYPES.has(detected.mime)) {
    return res.status(415).json({ error: 'Unsupported or unrecognized file type' });
  }

  const baseName = crypto.randomUUID();
  const storedName = `${baseName}.${detected.ext}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  // CWE-434 fix: use detected.ext instead of client-supplied extension
  await fs.writeFile(destination, req.file.buffer);

  res.status(201).json({ id: storedName });
});

module.exports = router;
```

## Explanation

The fix replaces `path.extname(req.file.originalname)` with `detected.ext`, sourcing the file extension from the detected file type rather than the client-supplied filename. The `file-type` library's `fileTypeFromBuffer()` returns both `mime` and `ext` properties; using `detected.ext` ensures the stored filename extension matches the file's actual content. This closes the vulnerability where an attacker could upload malicious content with a harmless MIME type but a dangerous extension (e.g., a polyglot PDF/JavaScript with `.php` extension), leading to code execution when the file is later accessed through a web server or script interpreter that trusts file extensions.

## Behaviour changes

Removed line 37 (`const clientExt = path.extname(req.file.originalname);`). Line 38 now computes `storedName` from `detected.ext` instead of `clientExt`. The stored filename's extension is now controlled by the detected file type, not client input. This is the security fix and does not introduce functional regression—the file is served through application-controlled routes, not via static file serving that would respect the extension for execution decisions.
