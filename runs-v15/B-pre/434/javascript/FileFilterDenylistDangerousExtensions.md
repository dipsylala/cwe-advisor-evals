## Verdict

CONFIRMED - CWE-434 Unrestricted Upload of File with Dangerous Type at line 22. The vulnerability uses a denylist of blocked extensions rather than an allowlist, trusts only the client-supplied filename extension without validating actual file content, and allows any file not in the short blocklist to be stored with its original name and extension.

## Source

Line 22 in the `fileFilter` callback returns `cb(null, true)` to permit upload of any file whose extension is not in the BLOCKED_EXTENSIONS list. The function validates only the extension (`file.originalname`) against a hardcoded denylist of 4 extensions, which is insufficient. The file is then stored at line 13 using the original client-supplied filename directly, creating multiple exploitation paths:

1. Attacker uploads PHP shell as `shell.php.jpg` - the extension check passes, the file is stored, and served as image (or executed if PHP processes `.jpg` files or a misconfigured server interprets double extensions)
2. Attacker uploads executable content with an allowed extension (e.g., valid JPEG image containing embedded PHP) - passes extension check because it has a permitted extension, but may be executable
3. Path traversal via `originalname` like `../../../shell.php` reaches outside the uploads directory
4. Hundreds of dangerous extensions exist beyond the 4 blocked (`.jsp`, `.asp`, `.phtml`, `.shtml`, `.jhtml`, `.cshtml`, `.vbhtml`, etc.)

The fileFilter callback cannot validate file content (magic bytes) because multer has not yet written the file to disk or buffer when fileFilter is called.

## Fix

Replace the denylist-based fileFilter with allowlist validation of actual file content in the route handler after upload completes:

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs').promises;

const router = express.Router();

// Allowlist of permitted MIME types derived from magic bytes
const ALLOWED_MIME_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'application/pdf': 'pdf',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  // Generate a temporary filename; replace with safe name after type detection
  filename: (req, file, cb) => cb(null, `${crypto.randomUUID()}.tmp`),
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB file size limit
});

router.post('/attachments', upload.single('attachment'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    // Read file buffer for magic byte validation
    const buffer = await fs.readFile(req.file.path);
    
    // Use dynamic import for file-type (ESM module in v17+)
    const { fileTypeFromBuffer } = await import('file-type');
    const detectedType = await fileTypeFromBuffer(buffer);

    // Reject if type cannot be detected or is not in allowlist
    if (!detectedType || !ALLOWED_MIME_TYPES[detectedType.mime]) {
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'File type not allowed' });
    }

    // Generate safe filename using the detected extension (not client-supplied)
    const safeFilename = `${req.file.filename.replace(/\.tmp$/, '')}.${detectedType.ext}`;
    const finalPath = path.join(__dirname, 'uploads', safeFilename);
    
    // Rename from temporary name to final name
    await fs.rename(req.file.path, finalPath);

    return res.status(201).json({
      message: 'Attachment uploaded',
      path: finalPath,
    });
  } catch (error) {
    // Clean up temporary file on validation failure
    if (req.file && req.file.path) {
      await fs.unlink(req.file.path).catch(() => {});
    }
    return res.status(500).json({ error: 'File upload failed' });
  }
});

module.exports = router;
```

## Explanation

The fix eliminates the denylist approach by:

1. **Removing the unsafe fileFilter** - No longer trusts `file.originalname` extension as a security gate
2. **Validating actual file content** - After the file is written to disk (when multer completes), reads its bytes and uses the `file-type` library to detect the actual MIME type by inspecting magic bytes, comparing against an allowlist rather than a denylist
3. **Generating a safe storage filename** - Uses `crypto.randomUUID()` with the extension derived from the detected type (e.g., `.jpg`, `.png`) rather than the client-supplied extension, breaking the attacker's ability to control the extension that the server uses when serving the file back
4. **Adding file size limits** - Sets `limits.fileSize` to 10 MB to prevent resource exhaustion attacks
5. **Cleaning up rejected files** - If validation fails, deletes the temporary file from disk immediately rather than leaving it in place

The allowlist of ALLOWED_MIME_TYPES contains only business-required types; anything not in this list is rejected regardless of what the client claims. The extension used for storage is derived from the detected type, ensuring the file is handled according to its actual content, not the attacker's chosen extension.

An attacker can no longer:
- Upload executable content as an allowed type (e.g., PHP as `.jpg`) because magic byte validation detects the true type
- Use extension tricks like `.php.jpg` because the stored extension comes from the detected type, not the filename
- Traverse directories because `crypto.randomUUID()` generates a flat, non-traversable name
- Exploit the blocklist gap because allowlist validation rejects anything not explicitly permitted

## Behaviour changes

1. **Route handler is now async** - To support the async `fileTypeFromBuffer()` check, the route callback is declared `async`
2. **Requires file-type dependency** - The fix depends on the `file-type` npm package; this must be added to package.json (`npm install file-type`)
3. **Different response structure** - The response now includes `filename` instead of `path` (or provide both as needed by the API contract)
4. **Rejection reason changes** - Files with unsupported types now return 400 "File type not allowed" instead of being accepted
5. **Temporary file cleanup** - Rejected uploads are cleaned from disk automatically; previously rejected files would remain in the uploads directory
6. **File extension in storage** - Uploaded files are now stored with extensions matching their detected MIME type (`.jpg`, `.png`, `.gif`, `.pdf`) rather than the original client-supplied extension
7. **No change to upload size or destination** - Files are still stored in the `uploads/` directory (as before); the fix does not change the webroot deployment path, but the route handler demonstrates the validation pattern and subsequent security hardening should store outside any `express.static()` root
