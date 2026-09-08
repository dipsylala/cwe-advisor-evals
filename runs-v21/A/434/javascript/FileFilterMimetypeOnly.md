## Verdict
VULNERABLE. The code validates MIME type but fails to validate file extension and does not verify actual file content. This allows attackers to upload dangerous file types by spoofing the MIME type header while preserving a dangerous extension in the original filename.

## Source
Line 24: `cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));`
Line 18: `const ext = path.extname(file.originalname);`

The vulnerability chain: the fileFilter only checks MIME type (which is client-controlled via the `Content-Type` header), but the filename generation on line 18 preserves the extension from `file.originalname` (also client-controlled). An attacker can upload a `.php` or `.js` file with `Content-Type: image/png` in the request header, pass the mimetype filter, and the file saves with its original dangerous extension.

## Fix

### File: FileFilterMimetypeOnly.js
```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, 'uploads', 'profile-photos');

const ALLOWED_MIMETYPES = ['image/png', 'image/jpeg'];
const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Map MIME type to a safe, fixed extension instead of using client-supplied extension
    const mimeToExt = {
      'image/png': '.png',
      'image/jpeg': '.jpg',
    };
    const ext = mimeToExt[file.mimetype] || '.bin';
    cb(null, `${crypto.randomUUID()}${ext}`);
  },
});

function fileFilter(req, file, cb) {
  // Validate MIME type against allowlist
  if (!ALLOWED_MIMETYPES.includes(file.mimetype)) {
    return cb(null, false);
  }
  
  // Validate extension against allowlist to prevent extension-based spoofing
  const ext = path.extname(file.originalname).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(null, false);
  }
  
  cb(null, true);
}

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter,
});

router.post('/profile/photo', upload.single('photo'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'photo rejected or missing' });
  }

  const photoUrl = `/uploads/profile-photos/${req.file.filename}`;
  return res.status(201).json({ url: photoUrl });
});

module.exports = router;
```

## Explanation

The fix implements two layers of validation to remediate CWE-434:

1. **Extension whitelist validation (line 37-40)**: Added validation that the client-supplied filename extension matches the allowed set `['.png', '.jpg', '.jpeg']`. This prevents attackers from uploading files with dangerous extensions like `.php`, `.js`, `.exe`, or `.sh` even if they spoof the MIME type header.

2. **Fixed extension assignment (line 16-22)**: Changed the filename generation to use a MIME-type-to-extension mapping instead of the client's `originalname` extension. This ensures the saved file extension is safe and matches what was validated. The mapping enforces that `image/png` uploads always get `.png` extension and `image/jpeg` uploads get `.jpg`, regardless of what the attacker claimed in the original filename.

**Defense-in-depth rationale**: MIME type alone is insufficient because the `Content-Type` header is client-controlled and easily forged. File extension validation adds a second check. Using a deterministic mapping from MIME type to extension ensures that even if validation logic is bypassed, the file extension cannot be manipulated independently.

For additional hardening against MIME type forgery, consider adding magic-bytes validation with a library like `file-type` to verify the actual file content matches the declared type.
