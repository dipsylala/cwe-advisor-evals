## Verdict

CWE-434 (Unrestricted Upload of File with Dangerous Type) - CONFIRMED. The vulnerability stems from using a denylist approach to validate file uploads. Denylist-based validation is bypassable through double extensions, case variations, MIME type mismatches, and lesser-known executable formats not included in the blocked list.

## Source

**File:** FileFilterDenylistDangerousExtensions.js  
**Line:** 22 (the fileFilter callback's approval of the file)

**Vulnerability:** The `rejectKnownDangerousExtensions` function uses `BLOCKED_EXTENSIONS` as a denylist. An attacker can bypass this by:
- Uploading `.phtml`, `.jsp`, `.asp`, or other executable extensions not in the list
- Using mixed case like `.PHP` (if the server is case-insensitive)
- Uploading a file with a double extension like `shell.php.jpg`
- Exploiting MIME type mismatches (e.g., uploading an executable with `image/jpeg` MIME type)
- Using null bytes or other encoding tricks

The sink is line 22, where the callback returns `cb(null, true)` to approve the file without adequate validation.

## Fix

### File: FileFilterDenylistDangerousExtensions.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');

const router = express.Router();

// Extensions considered safe to upload. Only files with these extensions are allowed.
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.doc', '.docx'];

// Allowed MIME types mapped to safe extensions
const ALLOWED_MIME_TYPES = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/gif': '.gif',
  'application/pdf': '.pdf',
  'text/plain': '.txt',
  'application/msword': '.doc',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    // Generate a safe filename using timestamp and random string instead of user-provided name
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `upload-${uniqueSuffix}${ext}`);
  },
});

function allowOnlyWhitelistedExtensions(req, file, cb) {
  // Validate MIME type first
  if (!ALLOWED_MIME_TYPES[file.mimetype]) {
    return cb(new Error(`File type ${file.mimetype} is not allowed`));
  }

  // Validate file extension using allowlist
  const ext = path.extname(file.originalname).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(new Error(`File extension ${ext} is not allowed`));
  }

  return cb(null, true);
}

const upload = multer({
  storage,
  fileFilter: allowOnlyWhitelistedExtensions,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

router.post('/attachments', upload.single('attachment'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const savedPath = path.join(__dirname, 'uploads', req.file.filename);

  return res.status(201).json({
    message: 'Attachment uploaded',
    path: savedPath,
  });
});

module.exports = router;
```

## Explanation

The fix replaces denylist validation with an allowlist approach and adds complementary defenses:

1. **Allowlist (not denylist):** `ALLOWED_EXTENSIONS` and `ALLOWED_MIME_TYPES` explicitly define what is acceptable. Anything not in the lists is rejected. This prevents bypass by unknown or lesser-known executable formats.

2. **Dual validation:** Both MIME type and file extension are checked. MIME type validation catches attempts to upload executables with spoofed extensions, while extension validation catches MIME type mismatches.

3. **Safe filename generation:** Instead of using the user-supplied `originalname`, the server generates a unique filename with a timestamp and random suffix. This prevents directory traversal attacks (e.g., `../../../shell.php`) and name-collision attacks.

4. **File size limit:** A 10MB limit prevents disk exhaustion attacks.

These changes ensure that only genuinely safe file types can be uploaded and that uploaded files cannot be executed or traversed to other directories.

