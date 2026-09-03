## Verdict

Exploitable. The `fileFilter` function on line 24 validates only `file.mimetype`, which is client-supplied in the HTTP request and not verified by multer. An attacker can forge the MIME type and upload a malicious file (e.g., a script) with a `.jpg` extension preserved from `file.originalname`, bypassing the allowlist check. The file is then stored with the attacker-controlled extension and served back to users.

## Source

The HTTP multipart request body: `file.mimetype` (client-supplied) and `file.originalname` (attacker-controlled path component).

## Fix

Remove the unsafe `fileFilter` logic that relies only on `file.mimetype`. Instead, validate the actual file content using magic-byte inspection after multer writes the file to disk. Use the `file-type` library to detect the real MIME type and regenerate the filename with a safe, detected extension.

**Vulnerable code (line 24):**
```javascript
function fileFilter(req, file, cb) {
  // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
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
```

**Fixed code:**
```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, 'uploads', 'profile-photos');

const ALLOWED_MIMETYPES = ['image/png', 'image/jpeg'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Generate a random filename without using the user-supplied extension
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
    // Validate file content using magic bytes
    const { fileTypeFromFile } = await import('file-type');
    const detected = await fileTypeFromFile(req.file.path);

    if (!detected || !ALLOWED_MIMETYPES.includes(detected.mime)) {
      // Delete the rejected file
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'Invalid file type' });
    }

    // Rename the file with the detected extension
    const finalPath = path.join(UPLOAD_DIR, `${req.file.filename}.${detected.ext}`);
    await fs.rename(req.file.path, finalPath);

    const photoUrl = `/uploads/profile-photos/${path.basename(finalPath)}`;
    return res.status(201).json({ url: photoUrl });
  } catch (error) {
    // Clean up on error
    if (req.file && req.file.path) {
      await fs.unlink(req.file.path).catch(() => {});
    }
    return res.status(500).json({ error: 'Upload processing failed' });
  }
});

module.exports = router;
```

## Explanation

The fix eliminates the vulnerability by moving validation from the unsafe `fileFilter` (where client-supplied MIME type is trusted) to the route handler after multer has written the file to disk. The `file-type` library's `fileTypeFromFile` inspects actual magic bytes to detect the real file format, making it impossible for an attacker to forge the type. Only files matching the allowlist MIME types pass validation. Files that fail validation are immediately deleted from disk. The stored filename is generated with `crypto.randomUUID()` and the extension is derived from the detected type (not `file.originalname`), ensuring the extension cannot be manipulated by the attacker to control how the file is served back. The route handler now uses `async/await` to handle the asynchronous file-type detection and filesystem operations, with error handling that cleans up partially-written files.

## Behaviour changes

1. **Route handler now async**: The route handler is now `async` to support `await import('file-type')` and `fs.promises` calls. This is safe; Express handles async route handlers correctly.
2. **Validation moved post-upload**: Validation now happens after multer writes the file, allowing magic-byte inspection. Rejected files are deleted immediately, so no invalid files persist on disk.
3. **File extension added post-upload**: The temporary random-named file is renamed with the detected extension, changing the filesystem state. This is intentional and necessary to control how the file is served.
4. **New dependency**: Requires the `file-type` npm package (ESM-only from v17+, so dynamic `import()` is used for CommonJS compatibility).
5. **Error handling**: Added try-catch block to clean up partial files on any error during type detection or renaming. Clients receive explicit error messages for validation failures.
6. **Rejection response**: Changed error response from generic "photo rejected or missing" to specific "Invalid file type" on validation failure, improving client feedback.
