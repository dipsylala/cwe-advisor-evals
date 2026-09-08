## Verdict

exploitable (confidence: high)

- cwe_id: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- location: `FileFilterMimetypeOnly.js`, line 24 (the `cb(null, ALLOWED_MIMETYPES.includes(file.mimetype))` call inside `fileFilter`)

## Source

`req` on `POST /profile/photo`, specifically the multipart file part's client-supplied `Content-Type` header, surfaced by `multer` as `file.mimetype`, and the client-supplied `file.originalname` used to derive the stored extension.

## Fix

The sink is `multer`'s `fileFilter`, which gates the upload only on `file.mimetype` (line 24) - a value multer copies verbatim from the multipart request's `Content-Type` header and never verifies against the file's actual bytes. An attacker sends a `photo` part with any content (e.g. a `.php` or `.html` web shell) and sets its part `Content-Type` to `image/png`; `fileFilter` sees an allowed mimetype and calls `cb(null, true)`, so `diskStorage` writes the file to `UPLOAD_DIR`. The stored filename is `crypto.randomUUID()` plus `path.extname(file.originalname)` (line 17-18) - the extension likewise comes straight from the client-supplied original filename, so the same request can also choose `.php` as the stored suffix. If `UPLOAD_DIR` (or anything under it) is ever served statically or by a handler that executes files by extension, the upload becomes a web shell.

Sink contract preserved by the fix:
- Returns: the route still responds `201 { url }` on success and `400 { error: 'photo rejected or missing' }` on rejection - both existing response shapes are unchanged.
- Discards: neither the original nor the fix surfaces `file.mimetype`/`file.originalname` in the response; nothing newly leaked.
- Implicit arguments: `multer()`'s `fileFilter` option is now omitted (multer's default is to accept every file at the middleware stage), because real verification is deferred to the route handler where content is actually available.
- Failure behaviour: multer's `limits.fileSize` still causes multer to `cb(new Error(...))` and reject oversized uploads before they reach the handler, unchanged from the original.

### File: FileFilterMimetypeOnly.js
```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs/promises');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, 'uploads', 'profile-photos');

// Fixed mime -> extension allowlist. The stored file's extension always
// comes from this map after content inspection, never from the client's
// filename or Content-Type header.
const ALLOWED_TYPES = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // The real type isn't known until the bytes are inspected after upload,
    // so store under a bare, extensionless random name for now; it is
    // renamed with a verified extension (or deleted) in the route handler.
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

  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);
  const ext = detected && ALLOWED_TYPES[detected.mime];

  if (!ext) {
    await fs.unlink(req.file.path);
    return res.status(400).json({ error: 'photo rejected or missing' });
  }

  const finalName = `${req.file.filename}.${ext}`;
  await fs.rename(req.file.path, path.join(UPLOAD_DIR, finalName));

  const photoUrl = `/uploads/profile-photos/${finalName}`;
  return res.status(201).json({ url: photoUrl });
});

module.exports = router;
```

**Library recommendation**: `file-type` (magic-byte detection via `fileTypeFromFile`). The loaded guidance names this library but records no minimum safe version for CWE-434 specifically - confirm the resolved version against SCA/dependency-check tooling before merging, and note that `file-type` is ESM-only from v17 onward, which is why it is loaded here with a dynamic `await import('file-type')` inside this CommonJS module rather than a top-level `require`. Add it to `package.json` dependencies; the exact version string was not added here since none is supplied by the loaded guidance.

## Explanation

The unsafe `fileFilter` mimetype check is removed entirely - multer now accepts any file that fits the size limit, since `file.mimetype` can never be trusted as a gate. `filename` no longer derives the stored extension from the client-supplied `file.originalname`; it stores the upload under a bare `crypto.randomUUID()` with no extension yet. After `upload.single('photo')` completes, the route handler reads the file's actual bytes from disk with `fileTypeFromFile(req.file.path)` and looks up the detected `mime` in the fixed `ALLOWED_TYPES` map; only a genuine PNG or JPEG produces a match. On success, the file is renamed to add the extension taken from that map (never from client input), so the extension that later governs how the file might be served is chosen entirely server-side from verified content. On failure, the written file is deleted with `fs.unlink` and the endpoint returns the same rejection response as before. This closes the CWE-434 gap because acceptance and the resulting stored filename now depend on inspected file content instead of attacker-supplied metadata.

## Behaviour changes

- Removed the `fileFilter` option from `multer()` (previously rejected based on `file.mimetype`) - reason: `file.mimetype` is attacker-controlled and cannot serve as a security gate; rejection is now based on verified content instead, performed after upload.
- Route handler is now `async` and, after multer writes the file, calls `fileTypeFromFile()` to detect the real content type - reason: content inspection requires the bytes to exist on disk, which is only true after `diskStorage` finishes writing, not inside `fileFilter`.
- A file whose real content does not match `ALLOWED_TYPES` is now deleted from disk with `fs.unlink` before the `400` response is sent - reason: previously such a file was never written (multer rejected it in `fileFilter`); now it is briefly written under an extensionless random name and must be cleaned up once found invalid. Net effect on the client-visible contract is unchanged (still `400 { error: 'photo rejected or missing' }`).
- Stored filename extension now comes from `ALLOWED_TYPES[detected.mime]` instead of `path.extname(file.originalname)`, and the file is renamed once verified - reason: per the loaded guidance, the extension decides how the file is later served and must be derived from detected content, not the client-supplied name; the `photoUrl` returned to the client changes accordingly (still `/uploads/profile-photos/<name>`, but `<name>` is `<uuid>.<verified-ext>` instead of `<uuid><client-supplied-ext>`).
- New dependency introduced: `file-type` (dynamically imported) - reason: required to perform magic-byte detection per the loaded language-specific guidance; not present in the original file.

## Verification

Ran `node --check` against the fixed file (copied to a scratch location, not the case directory) - passed with no syntax errors. No test runner or `package.json`/`node_modules` was available in the case directory to execute the route handler live or to confirm `file-type`'s exact installed API surface, so the following were checked by hand against the loaded guidance and file-type's documented API instead of executed: `fileTypeFromFile` is the named export documented for `file-type` v16+ for reading a file path (matches `cwe/434/javascript/INDEX.md`'s explicit example); `fs/promises`' `unlink` and `rename` are Node.js standard-library functions taking a single path (`rename` taking `(oldPath, newPath)`), used here with paths built from `req.file.path` and `path.join(UPLOAD_DIR, finalName)` consistent with their documented signatures; `multer`'s `diskStorage` `filename` callback signature `(req, file, cb)` and `req.file.path`/`req.file.filename` fields are unchanged from the original file's already-working usage of the same API. Assumption: the exact `file-type` version was not verified against a registry or lockfile (none present in the case directory) - flag for SCA confirmation before merging.

## Assumptions

- No `package.json` was present in the case directory, so `file-type` cannot be confirmed as an existing project dependency; it is assumed to be added as a new dependency, and its version must be resolved via SCA/dependency-check tooling rather than pinned here, per the loaded guidance's rule against supplying version numbers from recall.
- The extension-to-mime mapping (`ALLOWED_TYPES`) reuses the same two types as the original `ALLOWED_MIMETYPES` (`image/png`, `image/jpeg`) since no broader business requirement was stated; `image/jpeg` is mapped to the `jpg` extension by convention.
- No other file in the case directory serves the uploaded files back (e.g. via `express.static` or a download route), so no change was needed to response headers or a serving route; this conclusion is based on the single file provided in the call chain.
