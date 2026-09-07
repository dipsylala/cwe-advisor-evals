## Verdict
Confirmed. The vulnerability exists because the file extension is derived from the untrusted client-provided `req.file.originalname` instead of from the detected MIME type. An attacker can upload a file with valid image/PDF content but with a dangerous extension (e.g., `.exe`, `.php`), bypassing the MIME type validation.

## Source
Lines 37-38 extract the extension from the client-provided originalname and use it directly in the stored filename, without validating it against the detected MIME type.

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
  const detectedExt = detected.ext ? `.${detected.ext}` : '';
  const storedName = `${baseName}${detectedExt}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  await fs.writeFile(destination, req.file.buffer);

  res.status(201).json({ id: storedName });
});

module.exports = router;
```

## Explanation
The fix replaces the client-provided extension with the extension derived from the file-type detection. The `file-type` library's `detected.ext` property returns the correct extension (e.g., `'png'`, `'pdf'`) based on the actual file content, not the client's claimed filename. This ensures the file extension always matches the validated MIME type, preventing attackers from uploading executable files disguised with legitimate MIME types.

The key changes:
- Line 37 (now removed): Previously used `path.extname(req.file.originalname)`, which trusts the client
- Line 38 (now 38): Uses `detected.ext` from the MIME type detection instead, prepending a dot for the standard extension format
- This guarantee that the stored file extension is determined by the actual content, not the attacker-controlled originalname field
