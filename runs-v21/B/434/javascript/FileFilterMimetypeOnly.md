## Verdict

Exploitable. The `fileFilter` callback on line 24 accepts files based solely on the client-supplied `file.mimetype` header, which is not verified. An attacker can upload a malicious file (executable, PHP shell, or script) and set the `Content-Type` header to `image/png` or `image/jpeg` to pass the check. Additionally, the stored filename's extension is taken from the client-supplied `file.originalname`, so the attacker can choose both the extension and content of the uploaded file.

## Source

The client-supplied `file.mimetype` header in the multipart form upload (attacker-controlled request metadata).

Additionally, `file.originalname` is used to derive the stored file's extension at line 17-18.

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

const ALLOWED_TYPES = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, crypto.randomUUID());
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
    const { fileTypeFromFile } = await import('file-type');
    
    const detected = await fileTypeFromFile(req.file.path);
    
    if (!detected || !ALLOWED_TYPES[detected.mime]) {
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'file type not allowed' });
    }
    
    const finalFilename = `${req.file.filename}.${detected.ext}`;
    const finalPath = path.join(UPLOAD_DIR, finalFilename);
    await fs.rename(req.file.path, finalPath);
    
    const photoUrl = `/uploads/profile-photos/${finalFilename}`;
    return res.status(201).json({ url: photoUrl });
  } catch (error) {
    try {
      await fs.unlink(req.file.path);
    } catch (e) {
      // Ignore cleanup errors
    }
    return res.status(500).json({ error: 'upload processing failed' });
  }
});

module.exports = router;
```

## Explanation

The fix removes the unsafe `fileFilter` callback that only checked the client-supplied MIME type, and moves file-type validation into the route handler after multer has written the file to disk. The `file-type` library reads the actual magic bytes (file signature) to detect the true file type, which the attacker cannot forge. Files are validated against an `ALLOWED_TYPES` allowlist, and any file with a disallowed or undetectable type is deleted immediately. The stored filename now uses `crypto.randomUUID()` with no extension at all during storage, and only after validation does it receive the extension derived from the detected type (via `detected.ext`), not from the client-supplied `file.originalname`. This prevents the attacker from controlling the filename, extension, or final storage name, and ensures that only genuine images are accepted and stored.

## Behaviour changes

1. **fileFilter callback removed**: The multer configuration no longer includes a `fileFilter` callback. This removes the gate that only checked MIME type, shifting validation to the route handler where file content can be inspected. Files are no longer pre-filtered by client metadata; instead, validation happens after the file is written.

2. **Async route handler**: The route handler is now `async` to accommodate `await import('file-type')` and `await fs.unlink()` calls. The original route was synchronous.

3. **File extension changed at runtime**: Instead of assigning the final extension during the `filename` callback, the file is initially stored with just a UUID (no extension), then renamed after validation to add the extension from `detected.ext`. This ensures the stored filename cannot be influenced by the client.

4. **Allowlist validation of detected MIME type**: Files are now checked against `ALLOWED_TYPES` which maps MIME types to extensions. The original code had `ALLOWED_MIMETYPES` as a list but did not use it to derive the extension; the fix uses the detected type to do so.

5. **Error handling for magic byte detection**: If `fileTypeFromFile` returns `null` (unrecognized format), the file is deleted and a 400 response is returned. The original code had no content validation at all.

6. **File cleanup on validation failure**: Files that fail the magic byte check are immediately deleted from disk. The original code kept any file that passed the MIME-type check.

7. **Dependency change**: The fix requires the `file-type` package (ESM). The original code did not have this dependency. `file-type` is a standard library for magic-byte detection and is widely maintained; it must be added to `package.json` before this code can run.

8. **Import statement**: Added `const fs = require('fs').promises;` to support async file operations. The original did not include this.
