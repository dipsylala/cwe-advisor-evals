## Verdict
Exploitable

## Source
`file.originalname` from the multipart request (client-supplied metadata)

## Fix

**Vulnerable code (lines 7-23):**
```javascript
const BLOCKED_EXTENSIONS = ['.exe', '.php', '.sh', '.bat'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, file.originalname),
});

function rejectKnownDangerousExtensions(req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (BLOCKED_EXTENSIONS.includes(ext)) {
    return cb(new Error(`File type ${ext} is not allowed`));
  }
  return cb(null, true);
}

const upload = multer({
  storage,
  fileFilter: rejectKnownDangerousExtensions,
});
```

**Fixed code:**
```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const router = express.Router();

// Allowlist of permitted MIME types (whitelist approach)
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    // Generate a random filename; actual extension added after type detection
    cb(null, crypto.randomUUID());
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

router.post('/attachments', upload.single('attachment'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    // Verify file type by checking magic bytes after file is written
    const { fileTypeFromBuffer } = await import('file-type');
    const fileBuffer = fs.readFileSync(req.file.path);
    const detectedType = await fileTypeFromBuffer(fileBuffer);

    // Reject if type cannot be detected or is not in allowlist
    if (!detectedType || !ALLOWED_MIME_TYPES.includes(detectedType.mime)) {
      fs.unlinkSync(req.file.path); // Remove rejected file
      return res.status(400).json({ error: 'File type not allowed' });
    }

    // Rename file with extension from detected type (not client-supplied)
    const finalFilename = `${req.file.filename}.${detectedType.ext}`;
    const finalPath = path.join(__dirname, 'uploads', finalFilename);
    fs.renameSync(req.file.path, finalPath);

    return res.status(201).json({
      message: 'Attachment uploaded',
      path: finalPath,
    });
  } catch (err) {
    // Clean up on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    return res.status(500).json({ error: 'Upload processing failed' });
  }
});

module.exports = router;
```

## Explanation
The original code used a denylist approach (BLOCKED_EXTENSIONS), permitting any file extension not explicitly blocked. Attackers can easily bypass this by uploading dangerous file types not in the list (e.g., .jsp, .asp, .aspx, .phtml). The fix replaces the weak extension-based denylist with a content-based allowlist. After multer writes the file to disk, the route handler reads the actual file bytes and uses the `file-type` library to detect the real MIME type by examining magic numbers. Only files matching the allowlist of permitted types (image/jpeg, image/png, image/gif, application/pdf in this example) are accepted. The storage filename is generated using `crypto.randomUUID()` with the extension derived from the detected type, never from the client-supplied `originalname`. Files that fail the type check are immediately deleted from disk. The `limits.fileSize` configuration also adds a size constraint to prevent resource exhaustion.

## Behaviour changes
- **Route handler is now async**: The handler must await `file-type`'s detection, making the function asynchronous. The calling code must handle promise resolution. 
- **File retention on validation failure**: The original silently accepted invalid files; the fixed code removes them from disk immediately after detection fails, preventing accumulation of dangerous files.
- **Storage filename format changes**: Original used `file.originalname` directly; fixed code uses a random UUID with extension from detected type (e.g., `a1b2c3d4-e5f6-47g8-h9i0-j1k2l3m4n5o6.png`). Existing clients expecting the original filename in responses must be updated to handle the new format, though the filename is no longer exposed in the stored path.
- **Extension rewrite after upload**: The file is initially stored without extension, then renamed after type verification. This prevents serving a file with the wrong extension based on client supply.
- **Dependency added**: `file-type` package (ESM import via dynamic await import) is now required; must be added to package.json.
- **New error path**: Type detection failures now return 400 instead of accepting the file, and files are cleaned up to prevent disk accumulation.
