## Verdict

CONFIRMED. Line 23 uses `req.file.originalname` to construct the destination path without sanitization. This allows path traversal attacks (e.g., `../../../etc/passwd.png`) and filename-based attacks that can escape the intended directory or interfere with application logic, even though MIME type validation is performed.

## Source

```javascript
const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);
```

The sink is direct use of untrusted user input (`req.file.originalname`) in a file path construction, despite MIME type validation on content.

## Fix

### File: AvatarInStaticRoot.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

const app = express();
const upload = multer({ dest: '/tmp/incoming' });

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml'];
const MIME_TO_EXT = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/svg+xml': '.svg'
};

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  const ext = MIME_TO_EXT[detected.mime] || '.img';
  const safeFilename = crypto.randomUUID() + ext;
  const destination = path.join(PUBLIC_DIR, 'avatars', safeFilename);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + safeFilename });
});

module.exports = app;
```

## Explanation

The fix eliminates the reliance on user-supplied `req.file.originalname` by:

1. **Generating a safe filename**: Use `crypto.randomUUID()` to create a filename that cannot be exploited for path traversal (`../`) or other directory-escape techniques.

2. **Deriving extension from detected MIME type**: Map the validated MIME type to a safe file extension using a hardcoded lookup table (`MIME_TO_EXT`). This prevents attackers from controlling the file extension through the original filename.

3. **Never trusting user input in paths**: The UUID ensures the filename is under attacker control in neither content nor format, making it impossible to craft paths that escape the avatars directory.

The MIME type validation (already present on line 18) remains and continues to validate file content. The filename generation ensures the file is stored with a name the attacker cannot control, closing the CWE-434 vector even if an attacker bypasses or modifies validation.
