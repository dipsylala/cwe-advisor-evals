## Verdict

Confirmed CWE-434: The upload handler validates file content via magic-byte inspection but derives the stored file extension from the client-supplied `originalname` instead of from the detected file type. An attacker can upload a valid image with a `.php` extension and have it stored and potentially executed as a PHP script.

## Source

`E:\Github\cwe-advisor\evals\cases\434\javascript\ExtensionFromOriginalnameNotDetectedType\ExtensionFromOriginalnameNotDetectedType.js`, lines 37–38:

```javascript
const clientExt = path.extname(req.file.originalname);
const storedName = `${baseName}${clientExt}`;
```

`req.file.originalname` is attacker-controlled metadata from the multipart upload request. Although the file content is correctly validated at line 30 using `fileTypeFromBuffer`, the stored filename's extension comes from the unvalidated client-supplied name, allowing the attacker to choose the extension that determines how the file is later served or executed.

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
  const detectedExt = detected.ext;
  const storedName = `${baseName}.${detectedExt}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  await fs.writeFile(destination, req.file.buffer);

  res.status(201).json({ id: storedName });
});

module.exports = router;
```

## Explanation

The fix replaces the client-supplied extension with the extension derived from the detected file type. Line 37 now reads the extension from `detected.ext` (the result of the magic-byte validation) instead of from `req.file.originalname`. Line 38 uses this trusted extension when constructing the stored filename. The `file-type` library's `fileTypeFromBuffer` returns an object with both `mime` and `ext` properties once a type is detected; using `detected.ext` ensures the extension is tied to the validated content, breaking the taint chain. An attacker can no longer control the extension by choosing a misleading filename—the extension now reflects the actual file type as determined by its magic bytes.

## Behaviour changes

None externally observable. The stored file now carries an extension guaranteed to match its detected content type. The application's response to valid uploads remains unchanged. Uploads of files with invalid content or mismatched content/MIME type are already rejected by the existing validation at line 32 and continue to be rejected. The change only affects the filename extension recorded in storage; the file's bytes, size limit, response status, and format are unaltered.
