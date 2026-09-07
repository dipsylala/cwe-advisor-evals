## Verdict

This is a confirmed CWE-434 vulnerability. The fileFilter function on line 24 validates uploads solely by checking the `file.mimetype` header, which is attacker-controlled request metadata and provides no guarantee of actual file content. An attacker can upload a malicious executable while spoofing a permitted MIME type (e.g., "image/png") and the file will be accepted and stored inside the application directory with its original dangerous extension. The vulnerability is fixed by removing MIME-type-only validation from fileFilter, detecting actual file content via magic-byte inspection in the route handler after the file is written to disk, and deriving the storage extension from the detected type rather than the client-supplied filename.

## Source

**File:** `FileFilterMimetypeOnly.js`
**Line:** 24
**Code:** `cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));`

**Data flow:**
1. Client submits multipart upload with `photo` field, setting arbitrary `Content-Type` header to spoof file type
2. multer receives the request and calls fileFilter with the untrusted `file.mimetype` value from the Content-Type header
3. fileFilter passes the check if the spoofed mimetype is in ALLOWED_MIMETYPES
4. File is stored to disk with the original filename's extension (line 14: `path.extname(file.originalname)`)
5. File can be served back or executed if stored inside a web-accessible directory

The sink is the fileFilter callback's decision to accept the file based on untrusted metadata alone, without inspecting actual content.

## Fix

### File: FileFilterMimetypeOnly.js

```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, 'uploads', 'profile-photos');

// Allowlist of permitted MIME types
const ALLOWED_MIMETYPES = ['image/png', 'image/jpeg'];

// Map MIME types to safe extensions
const MIME_TO_EXT = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Generate a random filename without extension
    // Extension will be added based on detected file type
    cb(null, crypto.randomUUID());
  },
});

// Do not rely on fileFilter for content validation
// Validation happens in the route handler after file is written
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

router.post('/profile/photo', upload.single('photo'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'photo rejected or missing' });
  }

  try {
    // Dynamically import file-type (ESM-only from v17)
    const { fileTypeFromFile } = await import('file-type');
    
    // Detect actual file type from magic bytes
    const detected = await fileTypeFromFile(req.file.path);
    
    // Reject if type cannot be detected or is not in allowlist
    if (!detected || !ALLOWED_MIMETYPES.includes(detected.mime)) {
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'File type not allowed' });
    }
    
    // Get safe extension from detected type
    const safeExt = MIME_TO_EXT[detected.mime];
    if (!safeExt) {
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'File type not allowed' });
    }
    
    // Rename file with safe extension from detected type
    const filename = `${req.file.filename}${safeExt}`;
    const newPath = path.join(UPLOAD_DIR, filename);
    await fs.rename(req.file.path, newPath);
    
    const photoUrl = `/uploads/profile-photos/${filename}`;
    return res.status(201).json({ url: photoUrl });
  } catch (err) {
    // Clean up on error
    if (req.file && req.file.path) {
      try {
        await fs.unlink(req.file.path);
      } catch (unlinkErr) {
        // Ignore unlink errors
      }
    }
    return res.status(500).json({ error: 'Upload processing failed' });
  }
});

module.exports = router;
```

## Explanation

The fix eliminates CWE-434 by replacing MIME-type-only validation with actual content inspection:

1. **Removed untrusted fileFilter validation**: The original fileFilter checked only `file.mimetype`, which is client-controlled HTTP header data that an attacker can forge. This check is removed; multer now accepts all uploads into the temporary storage.

2. **Added magic-byte detection in the route handler**: After `upload.single('photo')` completes and the file exists on disk, the route handler uses the `file-type` library's `fileTypeFromFile()` to detect the actual file type by reading magic bytes (file header signatures). This detection cannot happen inside fileFilter because diskStorage has not yet written the file when fileFilter runs.

3. **Allowlist validation on detected type**: The detected MIME type is checked against `ALLOWED_MIMETYPES`. If the detected type is not in the allowlist or cannot be detected, the file is deleted and an error is returned. Validation uses the detected type, not the client-supplied `file.mimetype`.

4. **Generated filename with detected extension**: The stored filename is now `crypto.randomUUID()` (attacker cannot predict or control it) with an extension derived from the detected file type via the `MIME_TO_EXT` map. The original filename and its extension are never used for storage, eliminating extension-spoofing attacks.

5. **Taint breaking**: All subsequent decisions (storage location, response headers, file serving) use the detected type and generated filename, not any client-controlled value. The allowlist-matched type becomes the source of truth.

6. **Error handling and cleanup**: Files that fail validation or cause processing errors are deleted from disk, preventing orphaned malicious uploads.

The configuration preserves `limits.fileSize` to reject oversized uploads before they consume disk space, and storage remains outside the webroot (no `express.static()` is configured to serve `UPLOAD_DIR`).

## Behaviour changes

- **Validation timing**: Validation now occurs after file upload is complete, not during parsing. Clients receive upload-complete status before validation completes, then file-type validation responds.
- **File naming**: Uploaded files no longer retain the original filename or its extension; they receive UUIDs with extensions determined by detected type. This breaks any assumptions about predictable filenames.
- **Error responses**: Type mismatches that passed before (forged MIME type + dangerous content) now return 400 with "File type not allowed", and detection failures return the same error.
- **Async route handler**: The route handler is now async to support the async `fileTypeFromFile()` call. This is safe with Express; route handlers can be async.
- **Dynamic import**: The `file-type` module is imported dynamically inside the route handler using `await import()` because `file-type` v17+ is ESM-only and this is CommonJS context. This adds startup overhead per request; for production, consider top-level dynamic import in a CommonJS wrapper or converting to ESM.

The fix prevents upload-and-execute attacks by ensuring only files with genuine permitted content are stored, and even if stored, they cannot execute because the extension comes from actual content, not client control.
