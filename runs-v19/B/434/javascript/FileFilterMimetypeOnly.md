## Verdict

Exploitable. The code trusts the attacker-controlled `file.mimetype` header as the sole gate for filtering uploads. An attacker can upload a PHP web shell or other executable with a forged `Content-Type: image/png` header, bypassing the filter. The file is stored with an extension derived from the client-supplied `file.originalname`, allowing further extension-based attacks. The stored file is accessible via a direct URL path constructed from the filename, creating a webshell execution risk.

## Source

`file.mimetype` (multipart request Content-Type header, attacker-controlled) and `file.originalname` (multipart request filename, attacker-controlled).

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

const ALLOWED_MIMETYPES = new Map([
  ['image/png', 'png'],
  ['image/jpeg', 'jpg'],
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Use temporary name; will be renamed after content validation
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
    const { default: fileType } = await import('file-type');
    const detected = await fileType.fileTypeFromFile(req.file.path);

    if (!detected || !ALLOWED_MIMETYPES.has(detected.mime)) {
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'invalid file type' });
    }

    const ext = ALLOWED_MIMETYPES.get(detected.mime);
    const baseName = req.file.filename.replace(/\.tmp$/, '');
    const finalFilename = `${baseName}.${ext}`;
    const finalPath = path.join(UPLOAD_DIR, finalFilename);

    await fs.rename(req.file.path, finalPath);

    const photoUrl = `/uploads/profile-photos/${finalFilename}`;
    return res.status(201).json({ url: photoUrl });
  } catch (err) {
    try {
      await fs.unlink(req.file.path);
    } catch (unlinkErr) {
      // ignore unlink errors
    }
    return res.status(500).json({ error: 'upload processing failed' });
  }
});

module.exports = router;
```

## Explanation

The fix replaces client-controlled mimetype filtering with validation of actual file content using the `file-type` library. The `fileFilter` function that trusted the `Content-Type` header is removed entirely. Instead, after multer writes the file to disk with a temporary `.tmp` extension, the route handler reads the file bytes and calls `fileTypeFromFile()` to detect the actual MIME type and extension. The detected type is checked against an allowlist before the file is renamed to use the detected extension. If the file content does not match an allowed type, it is deleted and a 400 error is returned. The stored extension now comes from the detected content type, not from the client-supplied filename. This closes CWE-434 by ensuring uploaded files are validated by their actual bytes, not by headers or filenames under attacker control.

## Behaviour changes

1. **Route handler is now async**: The handler must await file-type validation and fs operations (fs.rename, fs.unlink). Calling code must handle the async nature; this does not affect the HTTP response contract.

2. **fileFilter removed**: The multer configuration no longer includes a fileFilter callback. All file acceptance decisions are now made in the route handler based on actual content validation instead of the client-supplied mimetype header.

3. **ALLOWED_MIMETYPES changed from array to Map**: Changed from `['image/png', 'image/jpeg']` to a Map with mime types as keys and file extensions as values. This allows the fix to map detected MIME types to their correct extensions without a separate table.

4. **Temporary filename strategy**: Files are now written with a `.tmp` extension in the storage handler, then renamed after validation. This ensures the final extension comes from detected content, not the client-supplied originalname.

5. **File deletion on validation failure**: Invalid files are now deleted from disk before returning a 400 error. The original code would have accepted and stored them.

6. **Error handling added**: A try-catch block ensures that any errors during validation or file operations trigger cleanup (deletion of temp file) and return a 500 error, preventing partial failures from leaving orphaned temp files.

7. **New dependency**: The fix introduces `file-type` library as a runtime dependency (ESM v17+, loaded via dynamic import). This must be added to package.json.

8. **Response difference on validation failure**: The original code silently rejected invalid uploads at the multer middleware level. The fixed code explicitly returns a 400 response with message "invalid file type" when content validation fails, providing client feedback.
