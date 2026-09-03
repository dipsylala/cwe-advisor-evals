## Verdict

The vulnerability is real and exploitable. The code relies solely on the client-supplied `file.mimetype` header as its security gate, which an attacker can forge to bypass the filter and upload arbitrary file types.

## Source

Line 24: `cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));`

The `file.mimetype` value comes from the multipart request's `Content-Type` field supplied by the client in the upload request, not from inspection of the file's actual bytes. An attacker can send a malicious executable file (e.g., a Node.js script, PHP shell, or compiled binary) with the `Content-Type: image/jpeg` header, and the filter will accept it.

## Fix

Remove the `fileFilter` validation on `file.mimetype` and replace it with content-based validation in the route handler after the file is written:

```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, 'uploads', 'profile-photos');

const ALLOWED_MIMETYPES = ['image/png', 'image/jpeg'];
const ALLOWED_EXTENSIONS = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Use a generated name with a placeholder extension; update after validation
    cb(null, `${crypto.randomUUID()}.tmp`);
  },
});

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
    
    // Validate against allowlist
    if (!detected || !ALLOWED_MIMETYPES.includes(detected.mime)) {
      // Reject and remove the uploaded file
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'Invalid file type' });
    }
    
    // Rename to final filename using detected extension
    const finalExt = ALLOWED_EXTENSIONS[detected.mime];
    const finalFilename = `${crypto.randomUUID()}.${finalExt}`;
    const finalPath = path.join(UPLOAD_DIR, finalFilename);
    
    await fs.rename(req.file.path, finalPath);
    
    const photoUrl = `/uploads/profile-photos/${finalFilename}`;
    return res.status(201).json({ url: photoUrl });
  } catch (err) {
    // Clean up on error
    try {
      await fs.unlink(req.file.path);
    } catch (e) {
      // Ignore cleanup errors
    }
    return res.status(500).json({ error: 'Upload processing failed' });
  }
});

module.exports = router;
```

## Explanation

The fix moves validation from the unreliable `fileFilter` callback (which runs before the file is available) to the route handler (which runs after the file is written). It uses the `file-type` library to inspect actual magic bytes and compare against an allowlist of permitted MIME types. Crucially, it uses the detected MIME type to derive the final stored extension via `ALLOWED_EXTENSIONS` map, ensuring the file's behavior on the filesystem matches its actual content—not the client-supplied filename or header.

The file is temporarily stored with a `.tmp` extension, validated, renamed to the correct extension, and unlinked if it fails validation. This approach satisfies multer's API (no validation inside `fileFilter`), blocks polymorphic or forged uploads, and ensures uploaded files cannot be executed regardless of extension tricks.

## Behaviour changes

- **Validation timing**: Moved from `fileFilter` (before write) to route handler (after write), allowing actual content inspection.
- **Extension source**: Changed from `file.originalname` (client-supplied) to detected MIME type's mapped extension.
- **Failure handling**: Files that fail validation are unlinked from disk; requests return 400 instead of being silently rejected by multer.
- **Error paths**: Added try-catch and cleanup logic to handle file-type detection failures and unlink on error.
- **Dependency**: Requires `file-type` package (check SCA for latest safe version); note it is ESM-only from v17, requiring dynamic import in CommonJS.
