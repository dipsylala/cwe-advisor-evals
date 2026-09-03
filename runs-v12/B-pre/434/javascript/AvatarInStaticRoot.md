## Verdict

Exploitable. The vulnerability allows path traversal or directory escape through an attacker-controlled filename, and the uploaded file is stored in the static webroot where it can be served to other users.

## Source

`req.file.originalname` - the client-supplied filename extracted from the multipart form request.

## Fix

**Vulnerable code (lines 1-28):**

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');

const app = express();
const upload = multer({ dest: '/tmp/incoming' });

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml'];

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // VULNERABLE: Uses req.file.originalname directly in path
  const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + path.basename(destination) });
});

module.exports = app;
```

**Fixed code:**

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

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // FIXED: Generate safe filename from detected type, never use originalname
  const filename = `${crypto.randomUUID()}.${detected.ext}`;
  const destination = path.join(PUBLIC_DIR, 'avatars', filename);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + path.basename(destination) });
});

module.exports = app;
```

## Explanation

The original code validated the file's MIME type against an allowlist using `file-type`, which correctly identifies actual file content rather than trusting client-supplied headers. However, it then used `req.file.originalname` - a value directly from the client's multipart request - as part of the storage path. This enables path traversal (e.g., filenames like `../../etc/passwd`) and directory escape attacks that could overwrite sensitive files or inject executable content into the static directory.

The fix generates a cryptographically random filename using `crypto.randomUUID()` and derives the file extension from the detection result's `detected.ext` property, which corresponds to the actual file content that passed the MIME type allowlist. This ensures the stored filename cannot be influenced by the attacker, and the extension always matches the verified file type. The file is now safe to store and serve from the static directory.

## Behaviour changes

None. The fix preserves the existing contract: `fs.rename` still moves the temporary file to the avatars directory, `fs.mkdir` still creates the directory with recursive option, and the response still returns a valid URL to the stored avatar. The only difference is that the filename is now generated securely rather than derived from untrusted input, which actually strengthens the path without changing behaviour.
