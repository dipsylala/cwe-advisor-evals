## Verdict

Confirmed. The `fileFilter` in `FileFilterDenylistDangerousExtensions.js` allows any upload whose extension is not on a small hardcoded blocklist (`.exe`, `.php`, `.sh`, `.bat`). Every other extension - `.phtml`, `.php5`, `.jsp`, `.asp`, `.html`, `.svg`, `.htaccess`, an extensionless name, etc. - reaches `cb(null, true)` at line 22 and is accepted and written to disk under the client-supplied `file.originalname` (line 13). Both the extension and the MIME type multer exposes on `file` are attacker-controlled request metadata, never verified against the file's actual bytes.

## Source

`req` multipart body received by the Express route at `POST /attachments` (line 30) -> `file.originalname` read inside `fileFilter` (line 17) and again inside the `diskStorage.filename` callback (line 13).

## Fix

Sink contract established before changing it:
- **Returns**: `fileFilter`'s callback (`cb`) has no return value the caller uses beyond the accept/reject decision; `diskStorage.filename`'s callback return value is the on-disk basename multer will use.
- **Discards**: the original code discards the actual file content entirely - no byte-level check is ever performed, before or after storage.
- **Arguments left implicit**: `multer()` is called with no `limits`, so `fileSize` is unbounded; `diskStorage.filename` was implicitly trusting `file.originalname` as safe to write verbatim.
- **Failure behaviour**: passing an `Error` to `cb` inside `fileFilter` causes multer to abort the upload and pass that error to Express's error-handling middleware (not the route handler) - the route's own `res.status(400)` branch only fires for "no file part in the request", not for a `fileFilter` rejection under the original code.

The fix (per `cwe/434/javascript/INDEX.md`) replaces the extension blocklist with a content-based allowlist checked in the route handler - `fileFilter` runs before the file's bytes exist on disk, so magic-byte detection cannot happen there. `diskStorage` now writes to a random name with no extension; after `upload.single()` completes, the handler reads the written file with `file-type`'s `fileTypeFromFile`, matches the detected MIME type against an allowlist, deletes the file and returns 400 on a mismatch, and otherwise renames the file to `<uuid>.<detected-ext>` before responding. The client-supplied name and extension never reach the filesystem or the response.

### File: FileFilterDenylistDangerousExtensions.js
```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

const router = express.Router();
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Allowlist of business-required content types, mapped to the extension
// used when the file is stored. Adjust the entries to the types this
// endpoint actually needs to accept.
const ALLOWED_TYPES = new Map([
  ['image/png', 'png'],
  ['image/jpeg', 'jpg'],
  ['application/pdf', 'pdf'],
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  // Store under a random name with no extension yet. The extension is
  // assigned only after the file's real content has been verified below,
  // so the client-supplied name/extension never reaches the filesystem.
  filename: (req, file, cb) => cb(null, crypto.randomUUID()),
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
});

router.post('/attachments', upload.single('attachment'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // multer's fileFilter runs before the bytes are available, so content is
  // verified here instead, once req.file.path points at the written file.
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);
  const allowedExt = detected && ALLOWED_TYPES.get(detected.mime);

  if (!allowedExt) {
    await fs.unlink(req.file.path);
    return res.status(400).json({ error: 'File type is not allowed' });
  }

  const finalName = `${req.file.filename}.${allowedExt}`;
  const finalPath = path.join(UPLOAD_DIR, finalName);
  await fs.rename(req.file.path, finalPath);

  return res.status(201).json({
    message: 'Attachment uploaded',
    path: finalPath,
  });
});

module.exports = router;
```

## Explanation

The blocklist approach is inverted: it enumerates a few dangerous extensions and treats everything else as safe by default, so the fix cannot be a bigger blocklist - it has to allowlist the file *content*. `fileFilter` executes before multer has written any bytes or populated a buffer, so `req.file.buffer`/`req.file.path` do not exist yet at that point; the check is moved into the route handler, after `upload.single('attachment')` has run and `req.file.path` points at a real file on disk. `file-type`'s `fileTypeFromFile` reads the file's magic bytes and returns the detected `mime`/`ext`, which is matched against `ALLOWED_TYPES` - a small, business-defined set rather than a denylist. The stored extension is taken from that detection result, never from `file.originalname`, closing the second half of the weakness: even if an attacker's claimed extension were somehow permitted, the extension actually used when serving or interpreting the file is the one the allowlist maps to for the verified content type. A file whose real bytes don't match an allowed type is deleted (`fs.unlink`) rather than left on disk. `diskStorage.filename` also stops using `file.originalname` and generates a `crypto.randomUUID()` name instead, so the original filename - including any path-like content it might otherwise have carried into the write - never becomes part of the storage path. `limits.fileSize` caps the accepted size, which the original configuration left unbounded.

## Behaviour changes

- Route handler is now `async` (required to await `file-type` detection and the delete/rename operations); this changes only the handler's internal execution, not its request/response contract.
- Response `path` for a successful upload now points at `<uploads>/<uuid>.<detected-ext>` instead of `<uploads>/<original filename>` - callers that depended on the response echoing the client-chosen filename will see a different value. This is required by the fix: the stored filename is exactly what must not be attacker-controlled or attacker-guessable.
- Uploads are now rejected (`400 File type is not allowed`) whenever the actual file content is not PNG, JPEG, or PDF, even if the extension/MIME type the client supplied would previously have passed the blocklist. `ALLOWED_TYPES` is an assumption about the endpoint's real business need (labelled "attachment") - narrowed to three common document/image types since the original code and case did not state which types the endpoint must support; this list should be adjusted to match the actual accepted attachment types before deployment.
- `multer()` now sets `limits: { fileSize: 10 * 1024 * 1024 }` (10 MB). No size limit was specified anywhere in the original code or by the guidance beyond "set a limit," so this figure is an assumption and should be tuned to the endpoint's real requirements.
- New dependency: `file-type` (npm). No version is supplied here per policy - resolve the current version and confirm it against SCA/dependency-check tooling before merging; note the package is ESM-only from v17 onward, hence the dynamic `await import('file-type')` in a CommonJS file.
- Verification performed: `node --check` on the fixed file, run from a scratch copy outside the repository, returned no syntax errors. `fileTypeFromFile`, `crypto.randomUUID()`, and `fs/promises` (`unlink`, `rename`) are named directly in `cwe/434/javascript/INDEX.md` or are Node.js standard library; no other new name was introduced.
