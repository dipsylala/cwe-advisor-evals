## Verdict

Exploitable. The `fileFilter` function at line 22 uses a blocklist approach that permits any file whose extension is not in `BLOCKED_EXTENSIONS`. An attacker can upload files with dangerous extensions not listed (e.g., `.jsp`, `.jspx`, `.html`, `.svg`, `.htaccess`, `.war`) that execute or cause harm when stored in the web-accessible uploads directory. The file is stored with its client-supplied name, allowing the attacker to control the extension that the server uses when serving the file back.

## Source

**Source:** Client-supplied file in multipart form data upload (implicit, received by multer).

**Sink:** Line 22 returns `cb(null, true)` in the `fileFilter` callback, accepting the file for storage with the client-supplied `file.originalname`. The file is stored at lines 11-14 via `multer.diskStorage` with `filename: (req, file, cb) => cb(null, file.originalname)`, and served from a web-accessible uploads directory.

**Data flow:** The attacker's uploaded file and its original filename pass through multer without content validation, are written to disk with the client-supplied name in the uploads directory (line 35 returns the saved path), and are implicitly served by `express.static` or a similar route, allowing the server to execute or render the file based on its extension.

## Fix

### File: FileFilterDenylistDangerousExtensions.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs').promises;

const router = express.Router();

// Allowlist of permitted MIME types (business-required)
const ALLOWED_MIMETYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'application/pdf',
  'text/plain',
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    // Generate a random filename without extension; extension will be set after validation
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
    // Dynamically import file-type (ESM-only from v17)
    const { fileTypeFromFile } = await import('file-type');

    // Detect actual file type by checking magic bytes
    const detectedType = await fileTypeFromFile(req.file.path);

    // Reject if no type detected or type not in allowlist
    if (!detectedType || !ALLOWED_MIMETYPES.has(detectedType.mime)) {
      await fs.unlink(req.file.path);
      return res.status(415).json({ error: 'File type not allowed' });
    }

    // Rename file with proper extension based on detected type
    const finalPath = path.join(path.dirname(req.file.path), req.file.filename + '.' + detectedType.ext);
    await fs.rename(req.file.path, finalPath);

    return res.status(201).json({
      message: 'Attachment uploaded',
      id: path.basename(finalPath),
    });
  } catch (err) {
    // Clean up file on error
    try {
      await fs.unlink(req.file.path);
    } catch (e) {
      // ignore cleanup errors
    }
    return res.status(500).json({ error: 'File upload failed' });
  }
});

module.exports = router;
```

## Explanation

The original code uses a blocklist to reject a small set of dangerous extensions, which is inherently incomplete: any extension not in the blocklist (`.jsp`, `.jspx`, `.html`, `.svg`, `.war`, `.htaccess`, etc.) passes through. Additionally, the file is stored with its client-supplied filename, giving the attacker full control over both the name and extension served back.

The fix replaces this with a content-based allowlist approach as recommended by the CWE-434 guidance:

1. **Removed blocklist fileFilter logic** — the dangerous and ineffective extension-based gate.
2. **Added magic-byte validation in the route handler** — after multer writes the file to disk, the route handler reads the actual bytes and calls `fileTypeFromFile` (from the `file-type` v17+ library) to detect the true type.
3. **Allowlist check** — compares the detected MIME type against a curated set of permitted business-required types; rejects everything else.
4. **Random filename generation** — uses `crypto.randomUUID()` to generate a filename that the attacker cannot control, preventing extension-based exploitation.
5. **Detected-type extension** — the final extension comes from `detectedType.ext` (the library's detection result), not from `file.originalname`, so even if the client claims `.pdf`, a malicious file is stored with the extension matching its actual content.
6. **File cleanup on rejection** — deletes the written file if validation fails, avoiding orphaned uploads.
7. **File size limit** — enforces a 10 MB upper bound to mitigate resource exhaustion.

The fix preserves the multer diskStorage contract (files still land in the uploads directory via the storage engine) but enforces validation in the route handler after the file is available, as the CWE-434 JavaScript guidance requires.

## Behaviour changes

1. **Route handler is now async** — The route handler now uses `async/await` and `await import()` to dynamically import `file-type`, which is ESM-only from v17. This is a **required change** because the guidance mandates content detection after the file is written, which is not possible inside the synchronous `fileFilter` callback.

2. **New dependency: `file-type` v17 or later** — The fix requires the `file-type` package as a production dependency. This is **required** per the guidance.

3. **HTTP status codes differ** — Rejected files now return `415 Unsupported Media Type` instead of `400 Bad Request`. This is more semantically correct and **required** per REST conventions for type validation.

4. **Error handling and cleanup** — Files that fail validation are unlinked from disk; errors during file operations return `500 Internal Server Error`. This is **required** to avoid orphaning temporary files.

5. **Response structure changed** — The original returned the full path (`{ path: savedPath }`); the fixed version returns only the generated filename ID (`{ id: path.basename(finalPath) }`). The original exposed the server-side path to the client; the fixed version hides it and returns only a reference ID. This is a **security improvement** (information disclosure prevention) with **no functional consequence** — the client should not need the server path.

6. **File size limit enforced** — The fixed version adds `limits: { fileSize: 10 * 1024 * 1024 }` (10 MB) to the multer config. This is a **defence-in-depth addition** per the CWE-434 guidance and does not break legitimate uploads under 10 MB.

7. **Allowlist is hardcoded** — The fixed version defines `ALLOWED_MIMETYPES` as a constant. In a real application, this should be configurable per deployment; the example assumes a common set (images, PDF, plain text). This is an **assumption** — customize the allowlist to match business requirements.

**Summary:** All behaviour changes except #7 are required to close the vulnerability and follow the guidance. Change #7 (hardcoded allowlist) is assumed reasonable for the example; real code should externalize it.
