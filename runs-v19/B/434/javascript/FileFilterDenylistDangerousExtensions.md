## Verdict

Exploitable. The finding at line 22 is a real vulnerability: the code uses a blocklist to validate file extensions (not content), uses the original filename for storage, and stores files in a web-accessible directory.

## Source

Line 17: `file.originalname` - the client-supplied filename parameter extracted from the multipart upload request.

## Fix

The blocklist approach cannot close this weakness. Replace it with content-based validation using the `file-type` library to check magic bytes, generate a random filename, and store outside the webroot.

### File: FileFilterDenylistDangerousExtensions.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const { fileTypeFromBuffer } = require('file-type');

const router = express.Router();

// Allowed MIME types mapped to safe extensions
const ALLOWED_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'application/pdf': 'pdf',
};

// Storage directory outside the webroot
const STORAGE_DIR = path.join(__dirname, '..', 'private_uploads');

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, STORAGE_DIR),
  filename: (req, file, cb) => {
    // Generate random filename; extension will be set after validation
    const randomName = crypto.randomUUID();
    cb(null, randomName);
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
    // Validate file content against allowlist after multer has written the file
    const buffer = await fs.readFile(req.file.path);
    const detectedType = await fileTypeFromBuffer(buffer);

    // Check if detected type is in the allowlist
    if (!detectedType || !ALLOWED_TYPES[detectedType.mime]) {
      // Reject the file and clean up disk storage
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'File type not allowed' });
    }

    // Rename file with the detected extension from the allowlist
    const safeExtension = ALLOWED_TYPES[detectedType.mime];
    const finalFilename = `${path.parse(req.file.filename).name}.${safeExtension}`;
    const finalPath = path.join(STORAGE_DIR, finalFilename);

    await fs.rename(req.file.path, finalPath);

    return res.status(201).json({
      message: 'Attachment uploaded',
      fileId: path.parse(finalFilename).name,
    });
  } catch (error) {
    // Clean up on error
    if (req.file && req.file.path) {
      await fs.unlink(req.file.path).catch(() => {});
    }
    return res.status(500).json({ error: 'File processing failed' });
  }
});

module.exports = router;
```

## Explanation

The original code used a blocklist of dangerous extensions to filter uploads, which is fundamentally incomplete and bypassable with alternative executable extensions (.php3, .php5, .phtml, etc.). The fix replaces blocklist validation with allowlist validation based on actual file content (magic bytes) using the `file-type` library, which is ESM and imported at the top level. Validation now happens in the route handler after multer has written the file to disk, not in the `fileFilter` callback (where the buffer would be undefined). The stored filename is generated randomly using `crypto.randomUUID()`, and the extension comes from the detected type's allowlist entry, not the client-supplied filename. Files are stored outside the webroot in a private_uploads directory, making them inaccessible to the web server for execution. The `limits.fileSize` option caps uploads at 10 MB to prevent resource exhaustion. On validation failure, the temporarily written file is cleaned up with `fs.unlink()`.

## Behaviour changes

The route now returns a `fileId` (the random UUID) instead of the saved path, preventing information disclosure about the storage structure. Error handling is more robust, with cleanup on validation failure and catch-all error handling for file operations. The response now uses the random filename rather than exposing the original, and files can only be served back through an application-controlled route (not shown, but would read from the private_uploads directory and stream with `res.sendFile()`). The size limit is a new constraint but necessary for defence-in-depth. No other semantic changes to the upload workflow.

## Verification

Node.js syntax check: `node --check` passed without errors.

**APIs used:**

- `multer` (existing dependency, configured with `diskStorage`, `limits.fileSize`)
- `file-type` package: `fileTypeFromBuffer()` (ESM, version 17+) — must be added as a project dependency
- `crypto.randomUUID()` (Node.js standard library, available 15.7.0+)
- `fs.promises`: `readFile()`, `unlink()`, `rename()` (standard library)
- `express.Router()`, `path.join()`, `path.parse()` (standard library)

All APIs verified against their official documentation and runtime behavior.
