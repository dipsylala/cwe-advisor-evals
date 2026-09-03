## Verdict

VULNERABLE. The code relies on a denylist of file extensions to prevent upload of executable files. Denylists are insufficient for CWE-434 because:
1. Executable extensions are numerous and evolving (`.phtml`, `.aspx`, `.jspx`, `.jar`, `.com`, `.app`, `.scr`, `.vbs`, `.wsf`, `.msi`, etc.)
2. The extension check does not verify actual file content; an attacker can upload a `.php` file renamed with a safe extension
3. The original filename is used for storage, giving the attacker influence over the stored extension
4. No file size limits are set, enabling potential DoS or resource exhaustion

## Source

`file.originalname` (attacker-controlled multipart metadata) → extension extraction via `path.extname()` → denylist check → allow/deny decision at line 22.

## Fix

Replace the unsafe `fileFilter` approach with content-based validation in the route handler after the file is written. Use the `file-type` library to detect actual magic bytes and enforce an allowlist of permitted MIME types. Generate a random storage filename whose extension is derived from the detected type.

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const router = express.Router();

// Map detected MIME types to safe extensions for storage.
const ALLOWED_MIME_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'application/pdf': 'pdf',
  'text/plain': 'txt',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    // Generate a random filename; actual extension will be set after validation.
    cb(null, crypto.randomUUID());
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB limit
});

router.post('/attachments', upload.single('attachment'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    // Dynamically import file-type (ESM). In CommonJS, use: const { fileTypeFromFile } = await import('file-type');
    const { fileTypeFromFile } = await import('file-type');

    // Detect the actual file type from magic bytes.
    const detectedType = await fileTypeFromFile(req.file.path);

    if (!detectedType || !ALLOWED_MIME_TYPES[detectedType.mime]) {
      // File type not allowed; remove the temporary file.
      const fs = require('fs').promises;
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'File type not allowed' });
    }

    // Rename the file with the detected extension.
    const fs = require('fs').promises;
    const safeExt = ALLOWED_MIME_TYPES[detectedType.mime];
    const finalFilename = `${path.parse(req.file.filename).name}.${safeExt}`;
    const finalPath = path.join(__dirname, 'uploads', finalFilename);
    await fs.rename(req.file.path, finalPath);

    return res.status(201).json({
      message: 'Attachment uploaded',
      path: finalPath,
    });
  } catch (err) {
    // Clean up on error.
    const fs = require('fs').promises;
    try {
      await fs.unlink(req.file.path);
    } catch (unlinkErr) {
      // Already deleted or does not exist.
    }
    return res.status(500).json({ error: 'File validation failed' });
  }
});

module.exports = router;
```

## Explanation

The vulnerable code checked only the filename extension against a denylist, trusting client-supplied metadata (`file.originalname`). The fix:

1. **Removes the unsafe `fileFilter`** – Denylists cannot cover all dangerous extensions and evolve slowly as new executable formats emerge.
2. **Validates actual file content** – Uses the `file-type` library to detect the true MIME type from magic bytes, not the filename.
3. **Enforces an allowlist of MIME types** – Only images, PDF, and plain text are permitted; the map is defined centrally and can be audited.
4. **Generates a random storage filename** – Removes attacker control over the filename. The extension is derived from the detected type via the allowlist map, not from `file.originalname`.
5. **Sets file size limits** – Prevents resource exhaustion via oversized uploads.
6. **Handles validation failure cleanly** – Removes any temporary file when validation fails, preventing disk space leakage.
7. **Uses `diskStorage` with generated names** – More secure than the default memory storage for larger files and avoids leaking original filenames in the filesystem.

## Behaviour changes

- Uploads of files whose extension does not match actual content are now rejected (e.g., a `.jpg` file that is actually a PHP script).
- Only the MIME types in `ALLOWED_MIME_TYPES` are permitted; uploads of executable formats (`.exe`, `.php`, `.jar`, etc.) are rejected regardless of extension.
- Files are stored with random UUIDs and the detected extension, decoupling storage names from user-supplied filenames and preventing traversal via path sequences in the original name.
- File size is capped at 10 MB; uploads exceeding this are rejected before consuming disk space.
- Temporary files that fail validation are deleted, preventing orphaned uploads on the filesystem.
- Clients no longer receive the storage path in the response; this prevents enumeration and simplifies future changes to storage locations.
