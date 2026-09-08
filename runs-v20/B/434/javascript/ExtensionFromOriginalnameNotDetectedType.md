## Verdict

exploitable (confidence: high)

- cwe_id: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- location: `ExtensionFromOriginalnameNotDetectedType.js`, line 42 (`fs.writeFile` sink); root cause at line 37-38

## Source

`req.file` from the `upload.single('document')` multer middleware (memory storage) - specifically `req.file.originalname`, the client-supplied filename in the multipart request, which multer does not verify against the file's actual content.

## Fix

### File: ExtensionFromOriginalnameNotDetectedType.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs/promises');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, 'private-uploads');

const ALLOWED_MIME_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'application/pdf',
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

router.post('/documents', upload.single('document'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // file-type is ESM-only from v17, so this CommonJS handler loads it dynamically.
  const { fileTypeFromBuffer } = await import('file-type');
  const detected = await fileTypeFromBuffer(req.file.buffer);

  if (!detected || !ALLOWED_MIME_TYPES.has(detected.mime)) {
    return res.status(415).json({ error: 'Unsupported or unrecognized file type' });
  }

  const baseName = crypto.randomUUID();
  const storedName = `${baseName}.${detected.ext}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  await fs.writeFile(destination, req.file.buffer);

  res.status(201).json({ id: storedName });
});

module.exports = router;
```

## Explanation

The handler already does content-sniffing correctly (`fileTypeFromBuffer` against an allowlist of MIME types) and already randomizes the base filename with `crypto.randomUUID()`, but it then reattached the *extension* from `req.file.originalname` - attacker-controlled request metadata that `fileTypeFromBuffer` never inspects. An attacker can upload a payload whose bytes pass the PNG/JPEG/GIF/PDF magic-byte check while naming the file `payload.php`, `payload.html`, or similar, producing a stored file whose extension - the part that decides how a later handler, static file server, or OS will interpret it - is entirely attacker-chosen despite the content check appearing to gate the upload. The fix removes `path.extname(req.file.originalname)` entirely and instead builds the stored filename's extension from `detected.ext`, the value `file-type` derives from the same magic-byte inspection already used for the MIME allowlist check. This ties the stored extension to the verified content type rather than to client-supplied metadata, closing the gap between what was validated and what was persisted.

## Behaviour changes

- The stored file's extension now always matches the sniffed content type (e.g., a real PNG is stored as `.png` per `file-type`'s canonical extension) rather than whatever suffix the client's original filename happened to carry. For a legitimate upload where the client's extension already matched its true type, the stored extension is unchanged in practice; for an upload whose original filename had a mismatched or missing extension, the stored file now gets the extension corresponding to its real, verified content instead of the client's chosen suffix. This is the intended effect of the fix, not an incidental side effect.
- `clientExt` (`path.extname(req.file.originalname)`) is removed; it was used only to build `storedName` and has no other reader. `path` remains imported and used (`path.join` for `UPLOAD_DIR` and `destination`).
- No other arguments, return values, response bodies, or status codes changed. The `fs.writeFile` sink contract (returns a Promise<void>, no return value used by the caller, throws on I/O failure which is unhandled in both the original and fixed code) is unchanged.

## Verification

Ran `node --check` against the fixed file in a scratch location outside the codebase: passed with no syntax errors. `detected.ext` is a documented property of the `file-type` package's `FileTypeResult` (alongside `mime`, already used on the line above), matching the CWE-434 JavaScript guidance's instruction to use `detected.ext` from the same `fileTypeFromBuffer` call already present in the code; no new import or dependency was introduced.

Assumptions: `file-type`'s `ext` values (e.g. `png`, `jpg`, `gif`, `pdf`) are bare extensions without a leading dot, consistent with the package's documented output and with the interpolation `${baseName}.${detected.ext}` used here.
