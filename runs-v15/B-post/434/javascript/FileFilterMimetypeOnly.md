## Verdict

exploitable

## Source

`file.mimetype` from the HTTP multipart request in the `fileFilter` callback at line 24.

## Fix

**Vulnerable code** (lines 10, 22–25):

```javascript
const ALLOWED_MIMETYPES = ['image/png', 'image/jpeg'];

function fileFilter(req, file, cb) {
  // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
  cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));
}
```

**Fixed code**:

Replace the entire route handler with validation in the route itself after multer has processed the file:

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
    cb(null, `${crypto.randomUUID()}.tmp`);
  },
});

function fileFilter(req, file, cb) {
  cb(null, true);
}

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter,
});

router.post('/profile/photo', upload.single('photo'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'photo rejected or missing' });
  }

  try {
    const { fileTypeFromFile } = await import('file-type');
    
    const detected = await fileTypeFromFile(req.file.path);
    
    if (!detected || !ALLOWED_MIMETYPES.has(detected.mime)) {
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'Invalid file type' });
    }
    
    const correctExt = ALLOWED_MIMETYPES.get(detected.mime);
    const newPath = path.join(UPLOAD_DIR, `${path.parse(req.file.filename).name}.${correctExt}`);
    await fs.rename(req.file.path, newPath);
    
    const photoUrl = `/uploads/profile-photos/${path.basename(newPath)}`;
    return res.status(201).json({ url: photoUrl });
  } catch (error) {
    if (req.file && req.file.path) {
      await fs.unlink(req.file.path).catch(() => {});
    }
    return res.status(500).json({ error: 'Upload processing failed' });
  }
});

module.exports = router;
```

## Explanation

The original code validates file uploads by checking `file.mimetype`, which is attacker-controlled metadata sent in the HTTP multipart request header. An attacker can forge the Content-Type header to bypass the allowlist check while uploading arbitrary file content—for example, uploading an executable or HTML/SVG containing script as `image/png`.

The fix moves validation from `fileFilter` to the route handler and checks the actual file content using the `file-type` library's `fileTypeFromBuffer()` method against the detected MIME type's magic bytes. This occurs after multer has written the file to disk, ensuring the actual bytes are available for inspection. When a file's detected type does not match the allowlist, it is removed from disk before responding to the client. Additionally, the stored filename is regenerated using `crypto.randomUUID()` with the correct extension derived from the detected type, not the client-supplied original filename, preventing extension-spoofing attacks.

## Behaviour changes

- The `fileFilter` callback now accepts all files and defers the security decision to the route handler. This change is necessary because multer's `fileFilter` runs before the file is written to disk, so actual file content cannot be inspected there; accepting all files in `fileFilter` and validating after the file is available is the correct pattern in Node.js/multer.
- The route handler now includes async/await and a try/catch block to handle file validation and cleanup. The original code was synchronous; this version performs I/O operations (`fileTypeFromFile`, `fs.unlink`, `fs.rename`) that require async handling.
- Storage filename generation uses `.tmp` as a temporary extension (line 18 in fixed code). After validation succeeds, the file is renamed to the correct extension based on the detected MIME type, not the original filename. This breaks the attacker's control over the stored extension.
- The response on validation failure explicitly rejects with status 400 and an error message; the original code silently rejected during the multer stage.
- A `Map` replaces the array for ALLOWED_MIMETYPES to enable bidirectional lookup: MIME type → correct extension. This is required to derive the stored extension from detected content rather than from the client-supplied filename.
- Error handling: if file validation or renaming fails, the temporary file is unlinked to avoid leaving malicious uploads on disk. The original code had no cleanup on validation failure.
