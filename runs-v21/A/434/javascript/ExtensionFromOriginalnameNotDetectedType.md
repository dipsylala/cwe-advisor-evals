## Verdict
Confirmed: CWE-434 vulnerability. The code validates MIME type from file content but saves the file using the client-provided extension, allowing an attacker to upload a valid image/PDF with a dangerous extension like `.php`.

## Source
The vulnerability is in the file extension handling:
- Line 29-34: Correctly validates MIME type using `file-type` library to detect actual file content type
- Line 37: **Vulnerable**: Extracts extension from `req.file.originalname` (client-controlled input)
- Line 38: **Vulnerable**: Saves file with client-provided extension despite validated MIME type

An attacker can upload a legitimate PNG file but claim it is `shell.php` in the filename, bypassing the MIME type validation through the filename itself.

## Fix
Replace the client-provided extension with a safe extension derived from the validated MIME type:

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

// Map MIME types to safe extensions
const MIME_TO_EXT = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/gif': '.gif',
  'application/pdf': '.pdf',
};

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
  // Use the detected MIME type to determine the extension, not the client-provided one
  const safeExt = MIME_TO_EXT[detected.mime];
  const storedName = `${baseName}${safeExt}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
  await fs.writeFile(destination, req.file.buffer);

  res.status(201).json({ id: storedName });
});

module.exports = router;
```

## Explanation
The fix adds a `MIME_TO_EXT` mapping that associates each allowed MIME type with its corresponding safe extension. Instead of using `path.extname(req.file.originalname)` (client-controlled), the code now uses the MIME type detected by the `file-type` library to determine the extension. This ensures the file extension always matches the actual file content, preventing extension mismatch attacks. The attacker cannot claim a PNG is a PHP file because the extension will always be `.png` regardless of what was submitted in the `originalname` field.
