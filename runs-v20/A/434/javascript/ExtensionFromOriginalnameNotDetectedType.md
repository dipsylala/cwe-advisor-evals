## Verdict

Confirmed. The stored file's extension is taken from the client-supplied `req.file.originalname` (`path.extname(req.file.originalname)`) rather than from the content type actually detected by `fileTypeFromBuffer`. An attacker can upload a payload whose bytes satisfy an allowed magic-number check (e.g. a valid PNG) while naming the upload `payload.php`, `payload.html`, `payload.svg`, `payload.jsp`, etc. The MIME allowlist only gates the byte content; it never constrains the extension that ends up on disk. If the upload directory (or any path derived from it) is ever served statically, proxied, or handed to another process that dispatches on extension, the attacker controls the dangerous type via the filename even though the content check "passed".

## Source

`req.file.originalname` (attacker-controlled multipart field name, arrives via `upload.single('document')` at line 23) flows into `path.extname(req.file.originalname)` at line 37, producing `clientExt`, which is concatenated into `storedName` (line 38) and then into `destination` (line 39). That attacker-controlled extension reaches the filesystem write sink `fs.writeFile(destination, req.file.buffer)` at line 42.

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
  // Use the extension file-type derived from the actual file content, never the
  // client-supplied originalname - the two can disagree, and the disk extension
  // must reflect what the bytes were verified to be.
  const storedName = `${baseName}.${detected.ext}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  await fs.writeFile(destination, req.file.buffer);

  res.status(201).json({ id: storedName });
});

module.exports = router;
```

## Explanation

`fileTypeFromBuffer` returns both `mime` and `ext` derived from the same magic-number sniff of the actual content (e.g. `{ mime: 'image/png', ext: 'png' }`). The original code sniffs the content only to gate acceptance, then throws that result away and instead trusts `req.file.originalname` - a value the client fully controls and multer never validates - to decide what extension the file gets on disk. That reintroduces exactly the gap the content check was meant to close: the accepted bytes and the stored extension can name two different, unrelated types.

The fix replaces `path.extname(req.file.originalname)` with `detected.ext`, so the extension written to disk is always consistent with the content type that was actually verified. Because `detected.mime` is already constrained to `ALLOWED_MIME_TYPES`, `detected.ext` is implicitly constrained to the matching safe extension (`png`, `jpg`/`jpeg`, `gif`, `pdf`) - there is no longer any path by which an attacker-chosen filename can put a dangerous extension on a file that lands in `UPLOAD_DIR`. The original filename is no longer used for anything security-relevant (it isn't reflected in `storedName`, which remains a random UUID), so no separate sanitization of `originalname` is needed for this sink.
