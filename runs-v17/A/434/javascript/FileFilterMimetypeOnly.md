## Verdict

CONFIRMED - CWE-434 vulnerability. MIME type validation alone is insufficient for file upload security because MIME types are client-controlled and easily forged. Additionally, the file extension is extracted from the user-supplied `originalname`, allowing arbitrary dangerous extensions.

## Source

Line 24: `cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));`

This check only validates the MIME type reported by the client, which can be forged. An attacker can upload a malicious executable (e.g., `.exe`, `.sh`, `.bat`) with a spoofed MIME type like `image/jpeg`, and it will pass validation.

Line 18: `const ext = path.extname(file.originalname);`

The file extension is extracted from user-supplied `file.originalname`, which is completely unrestricted. Even with the MIME type check, the saved file can have any extension an attacker provides.

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

// Map MIME types to safe file extensions
const MIME_TO_EXT = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Use the mapped safe extension, not the user-supplied filename
    const ext = MIME_TO_EXT[file.mimetype] || '.bin';
    cb(null, `${crypto.randomUUID()}${ext}`);
  },
});

function fileFilter(req, file, cb) {
  cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));
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

The vulnerability stems from relying on MIME type validation alone. MIME types originate from the client request (`Content-Type` header) and cannot be trusted—an attacker can set any MIME type regardless of the actual file contents. Extracting the extension from `file.originalname` compounds the risk by allowing arbitrary file extensions.

The fix introduces a `MIME_TO_EXT` map that establishes a one-to-one correspondence between allowed MIME types and their safe file extensions. When generating the saved filename, the code now uses the mapped extension from the `MIME_TO_EXT` lookup instead of extracting it from the user-supplied `originalname`. This ensures that:

1. Only files with allowed MIME types pass the `fileFilter` check
2. The saved file receives a predetermined, safe extension matching its MIME type
3. An attacker cannot bypass this by uploading a malicious file with a spoofed MIME type or manipulating the filename

For any MIME type not in the map (which should not occur given the filter), a neutral `.bin` extension is used as a fallback, preventing execution.
