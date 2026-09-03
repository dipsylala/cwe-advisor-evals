## Verdict
Real vulnerability. The code relies solely on client-supplied MIME type validation without verifying file content or restricting file extensions, allowing an attacker to upload executable files disguised with an image MIME type.

## Source
Line 24: `cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));`

The `fileFilter` function accepts files based only on the `file.mimetype` field, which is client-controlled and can be spoofed. Additionally, line 18 preserves the client-supplied file extension without restriction: `path.extname(file.originalname)`.

## Fix
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
    // Use a safe extension from whitelist instead of client-supplied extension
    const ext = ALLOWED_EXTENSIONS[0]; // or match based on mimetype
    cb(null, `${crypto.randomUUID()}${ext}`);
  },
});

function fileFilter(req, file, cb) {
  // Validate MIME type against whitelist
  if (!ALLOWED_MIMETYPES.includes(file.mimetype)) {
    return cb(null, false);
  }

  // Validate file extension against whitelist
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
The original code checked only the client-supplied MIME type, which can be spoofed. An attacker can send a PHP, JSP, or other executable file with a fake `image/png` MIME type, bypassing the validation.

The remediation applies three layers:

1. **Whitelist file extensions** (line 11): Define allowed extensions and validate the client-supplied filename extension against this list (lines 36–39). This prevents execution-capable extensions.

2. **Store files with safe extensions only** (line 18): Instead of preserving `file.originalname`'s extension, assign a whitelisted extension. This ensures uploaded files cannot be executed even if the upload directory is misconfigured.

3. **Validate MIME type** (line 35): Keep the MIME type check but treat it as a secondary control, not the sole defense. MIME type validation catches obvious misconfigurations but cannot be the only check.

For production, consider additional hardening: verify actual file content using file-type libraries (e.g., `file-type` npm package) to detect files disguised with misleading MIME types, store uploads outside the web root, and configure the server to deny execution in the upload directory via `.htaccess` (Apache) or equivalent.
