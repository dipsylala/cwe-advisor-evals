## Verdict
Exploitable. The file upload validation relies solely on the client-supplied `file.mimetype` header without verifying actual file content, and the storage filename uses the original extension from `file.originalname`, allowing an attacker to upload a malicious script with a spoofed image MIME type.

## Source
Client-supplied multipart form data: `file.originalname` (line 17) and `file.mimetype` (line 24). An attacker can craft a POST request with a file claiming to be `image/png` while containing executable script.

## Fix
Replace the unsafe `fileFilter` with content-based validation in the route handler. Use the `file-type` library to inspect magic bytes after the file is written to disk. Store with a generated filename whose extension derives from the detected type, not the client-supplied original name.

**Vulnerable code (line 24):**
```javascript
function fileFilter(req, file, cb) {
  cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));
}
```

**Fixed code:**
```javascript
const fs = require('fs').promises;

const ALLOWED_TYPES = [
  { mime: 'image/png', ext: 'png' },
  { mime: 'image/jpeg', ext: 'jpg' }
];

const ALLOWED_MIMES = ALLOWED_TYPES.map(t => t.mime);
const MIME_TO_EXT = Object.fromEntries(ALLOWED_TYPES.map(t => [t.mime, t.ext]));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, `${crypto.randomUUID()}.tmp`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  // Remove the fileFilter that only checks mimetype
});

router.post('/profile/photo', upload.single('photo'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'photo rejected or missing' });
  }

  try {
    const { fileTypeFromFile } = await import('file-type');
    const detected = await fileTypeFromFile(req.file.path);

    if (!detected || !ALLOWED_MIMES.includes(detected.mime)) {
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'Invalid file type' });
    }

    const newFilename = `${crypto.randomUUID()}.${MIME_TO_EXT[detected.mime]}`;
    const newPath = path.join(UPLOAD_DIR, newFilename);
    await fs.rename(req.file.path, newPath);

    const photoUrl = `/uploads/profile-photos/${newFilename}`;
    return res.status(201).json({ url: photoUrl });
  } catch (err) {
    if (req.file && req.file.path) {
      await fs.unlink(req.file.path).catch(() => {});
    }
    return res.status(500).json({ error: 'File processing failed' });
  }
});
```

## Explanation
The original code trusted only the `file.mimetype` header—supplied by the client and not verified—to validate uploads, and used the original filename's extension for storage. An attacker can craft a request claiming `image/png` while uploading a `.js` file containing malicious script. The fix moves validation into the route handler where the file bytes are available on disk, uses the `file-type` library to inspect magic bytes and detect the actual MIME type, rejects files whose real type is not in the allowlist, and stores the file with an extension derived from the detected type (not the original filename). The temporary `.tmp` extension during storage and the check-then-rename sequence ensure the file is validated before being served with its final extension. This closes the gap between the claimed type and the actual content, and prevents extension spoofing.

## Behaviour changes
- The `fileFilter` function is removed entirely. multer now accepts all uploads of the specified size and stores them with a `.tmp` extension as a placeholder.
- Validation now occurs in the route handler after the file is written to disk, not during multer's filter phase. This is necessary because `file-type` requires access to the file bytes, which are not available during the `fileFilter` callback.
- The route handler is now `async` to support the asynchronous `fileTypeFromFile` call.
- On validation failure, the temporary file is deleted from disk and a 400 error is returned to the client.
- The stored filename now includes the extension derived from the detected type (`MIME_TO_EXT[detected.mime]`), ensuring the file is later served with the correct MIME type based on its actual content, not the client's claim.
- The `fs.promises` API is used for non-blocking file operations (unlink, rename).
- A try-catch block wraps the handler to ensure cleanup (unlink) occurs even if `fileTypeFromFile` or rename fails.
- Error handling adds a 500 response for file processing failures.
