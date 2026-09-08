## Verdict

Real issue. The code uses a denylist of dangerous extensions, which CWE-434 explicitly forbids. Attackers bypass this by uploading executable content with unlisted extensions (.phtml, .jsp, .asp, etc.) or double-extension techniques. Files are stored with the client-supplied original filename in a web-accessible directory, enabling direct execution of uploaded scripts.

## Source

Line 22: The `fileFilter` callback accepts files by calling `cb(null, true)` if the extension is not in BLOCKED_EXTENSIONS. The source is `file.originalname` (line 17), which is entirely client-controlled. The denylist approach is fundamentally weak: it cannot enumerate all dangerous types, and the extension is not verified against actual file content.

## Fix

Replace denylist filtering with allowlist-based content validation using the `file-type` library. Validate actual file magic bytes (not extension or MIME header) after multer writes the file. Store with a generated filename whose extension derives from the detected type, never from the client-supplied name. Add file size limits.

### File: FileFilterDenylistDangerousExtensions.js
```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs').promises;

const router = express.Router();

// Allowed MIME types and their corresponding safe extensions
const ALLOWED_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'application/pdf': 'pdf',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    // Generate a random UUID filename; extension will be added after type validation
    const randomName = crypto.randomUUID();
    cb(null, randomName);
  },
});

function rejectKnownDangerousExtensions(req, file, cb) {
  // Accept all files here; actual validation happens in the route handler
  // after the file has been written and we can inspect its content
  return cb(null, true);
}

const upload = multer({
  storage,
  fileFilter: rejectKnownDangerousExtensions,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB file size limit
});

router.post('/attachments', upload.single('attachment'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    // Dynamically import file-type (ESM-only from v17+)
    const { fileTypeFromFile } = await import('file-type');
    
    // Validate the file's actual content by checking magic bytes
    const detectedType = await fileTypeFromFile(req.file.path);
    
    // Check if the detected MIME type is in the allowlist
    if (!detectedType || !ALLOWED_TYPES[detectedType.mime]) {
      // File type not allowed; remove the uploaded file
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'File type not allowed' });
    }

    // Rename file with the correct extension from the detected type, not the client's original extension
    const basename = path.parse(req.file.filename).name;
    const newPath = path.join(__dirname, 'uploads', `${basename}.${detectedType.ext}`);
    await fs.rename(req.file.path, newPath);

    return res.status(201).json({
      message: 'Attachment uploaded',
      path: newPath,
    });
  } catch (err) {
    // Clean up on error
    try {
      await fs.unlink(req.file.path);
    } catch (unlinkErr) {
      // Ignore unlink errors during cleanup
    }
    return res.status(500).json({ error: 'File upload failed' });
  }
});

module.exports = router;
```

## Explanation

The fix applies three core principles from CWE-434 guidance:

1. **Allowlist validation by content, not extension**: The code no longer trusts `file.originalname` or checks a blocklist. Instead, `fileTypeFromFile()` inspects actual magic bytes to determine the true MIME type and compares it against an allowlist. This eliminates both the insufficient-denylist problem and the extension-spoofing attack.

2. **Generated storage filename with canonical extension**: Files are stored as random UUIDs (line 21) instead of using the client-supplied `originalname`. The extension is appended based on `detectedType.ext` from the allowlist map, ensuring the stored extension matches the detected content type, not the client's claim.

3. **Validation in route handler, not fileFilter**: The `fileFilter` middleware runs before the file is written to disk; at that point `fileTypeFromFile()` has no bytes to inspect and would fail. Validation is deferred to the route handler (lines 45-59), where the written file can be read and inspected. Files that fail the check are immediately deleted (line 56) to avoid leaving unwanted files in the uploads directory.

4. **File size limit**: The `limits.fileSize` configuration rejects uploads over 5MB before they consume memory or disk space, reducing attack surface.

5. **Async error handling**: Failed uploads are cleaned up and appropriate error responses are sent. Unlink errors during cleanup are caught to avoid masking the primary error.

## Behaviour changes

- **Narrower acceptance**: Only files with MIME signatures matching the allowlist (JPEG, PNG, GIF, PDF) are accepted. The previous implicit "accept anything not in BLOCKED_EXTENSIONS" is replaced with explicit allowlist enforcement.
- **Filename format change**: Stored files are now named as `<uuid>.<detected-ext>` (e.g., `a1b2c3d4-e5f6-47g8-h9i0-j1k2l3m4n5o6.jpg`) instead of the original client-supplied filename. This breaks any code that relies on the original filename being preserved, but eliminates directory traversal and execution-by-filename risks.
- **Async validation**: Type checking now runs asynchronously in the route handler rather than synchronously in `fileFilter`, introducing a brief window where a file sits on disk before validation. This is offset by immediate deletion on failure and is the correct pattern per CWE-434 JavaScript guidance (content detection is impossible in `fileFilter`).
- **New dependency**: Requires `file-type` package. Code uses dynamic `await import()` for v17+ ESM; for earlier versions, replace with CommonJS `require`.
- **File size limit enforced**: The original code accepted files of any size; uploads over 5MB are now rejected at the multer level.
