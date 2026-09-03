## Verdict
exploitable

## Source
`file.mimetype` from HTTP multipart Content-Type header in line 24

## Fix

**Vulnerable Code:**
```javascript
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${crypto.randomUUID()}${ext}`);
  },
});

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

**Fixed Code:**
```javascript
const fileType = require('file-type');
const fs = require('fs').promises;

const storage = multer.memoryStorage();

const ALLOWED_MIMETYPES = ['image/png', 'image/jpeg'];
const ALLOWED_EXTENSIONS = { 'png': '.png', 'jpeg': '.jpg' };

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

router.post('/profile/photo', upload.single('photo'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'photo rejected or missing' });
  }

  try {
    // Validate actual file content against magic bytes
    const detected = await fileType.fromBuffer(req.file.buffer);
    
    if (!detected || !ALLOWED_MIMETYPES.includes(detected.mime)) {
      return res.status(400).json({ error: 'file type not allowed' });
    }

    // Use detected extension, not client-supplied originalname
    const ext = ALLOWED_EXTENSIONS[detected.ext];
    if (!ext) {
      return res.status(400).json({ error: 'file type not allowed' });
    }

    const filename = `${crypto.randomUUID()}${ext}`;
    const filepath = path.join(UPLOAD_DIR, filename);
    
    // Write buffer to disk only after validation
    await fs.writeFile(filepath, req.file.buffer);
    
    const photoUrl = `/uploads/profile-photos/${filename}`;
    return res.status(201).json({ url: photoUrl });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: 'upload failed' });
  }
});
```

## Explanation
The original code trusts `file.mimetype`, which is the client-supplied Content-Type header in the multipart request—an attacker can set this to any value regardless of actual file content. The fix validates actual file content using `file-type`'s `fromBuffer()` method, which inspects magic bytes (file signatures) to detect the real type. The code now: (1) switches to memory storage to make the file buffer available during validation, (2) detects the actual MIME type from file bytes, (3) rejects files whose detected type is not in the allowlist, (4) derives the stored file extension from the detected type via a server-controlled map (never from `originalname`), and (5) writes to disk only after validation passes. This closes the weakness by validating content, not just headers, and storing with a generated name whose extension comes from the verified type.

## Behaviour changes
- Changed storage from diskStorage to memoryStorage: allows access to file buffer for content validation before writing to disk, avoids storing rejected uploads
- Removed fileFilter function: validation now occurs in the route handler after file buffer is available
- Added async/await in route handler: required for file-type detection and fs.writeFile operations
- Manual file write replaces multer's automatic storage: gives the application control to validate before storing
- Extension now derived from detected type (via ALLOWED_EXTENSIONS map), not from originalname: prevents extension-spoofing attacks where a .exe is renamed .png
- Returns 400 on invalid file type: matches existing error handling pattern
