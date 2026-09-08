## Verdict

Real vulnerability confirmed. The code validates the MIME type of uploaded files but then derives the stored filename extension from the client-supplied `req.file.originalname` rather than from the detected file type. An attacker can upload a valid PNG/JPEG/GIF/PDF file with a dangerous extension (e.g., `.php`, `.exe`, `.jsp`) in the original filename, causing the stored file to be treated as executable content when served back.

## Source

Lines 37-38 extract the extension from `req.file.originalname` (client-controlled) and use it to construct the stored filename:
```javascript
const clientExt = path.extname(req.file.originalname);
const storedName = `${baseName}${clientExt}`;
```

The extension determines how the file is served and whether it executes. Using the client-supplied extension defeats the purpose of the MIME type allowlist on lines 32-33.

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
  const storedExt = detected.ext;
  const storedName = `${baseName}.${storedExt}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  await fs.writeFile(destination, req.file.buffer);

  res.status(201).json({ id: storedName });
});

module.exports = router;
```

## Explanation

The fix changes lines 37-38 to derive the stored extension from the detected file type instead of the client-supplied filename. After the `file-type` library validates and detects the true MIME type, `detected.ext` provides the canonical extension for that type (e.g., `png` for `image/png`). The stored filename is now constructed as `{baseName}.{detectedExt}`, ensuring the extension matches the actual content regardless of what the attacker provided in `originalname`. This breaks the attack: a PNG file with a forged `.php` extension is stored as `.png` and served as an image, not executed.

The extension field `detected.ext` is safe to use because it comes from the file-type library's internal allowlist of known signatures, not from user input.

## Behaviour changes

The stored filename extension now reflects the detected MIME type rather than the client-supplied original filename. Files are served with extensions matching their actual content type. For example, a file uploaded as `malicious.php` containing PNG data will be stored as `{uuid}.png` instead of `{uuid}.php`, and will be served with the correct `Content-Type: image/png` header and extension. This prevents execution and enforces the intent of the MIME type allowlist.
