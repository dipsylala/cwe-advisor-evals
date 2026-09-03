## Verdict

**Confirmed**: CWE-434 (Unrestricted Upload of File with Dangerous Type)

The vulnerability is at line 37-38: after correctly validating file content using magic bytes and an allowlist, the code derives the stored filename extension from the client-supplied `req.file.originalname` instead of from the detected file type. An attacker can upload a valid PNG image with a `.php` extension in the filename, pass the content validation, and have it stored as `{uuid}.php`. If this directory is ever included, served, or accessed through a path traversal, the incorrect extension allows the server to treat the image as executable code.

## Source

The source is `req.file` from multer's `upload.single('document')` middleware (line 23). The client-supplied `originalname` is accessed at line 37 and used to construct the stored filename at line 38.

## Fix

Replace line 37-38:
```
  const clientExt = path.extname(req.file.originalname);
  const storedName = `${baseName}${clientExt}`;
```

With:
```
  const storedName = `${baseName}.${detected.ext}`;
```

The fix uses the file-type library's detected extension (`detected.ext` from line 30) instead of the client-supplied `req.file.originalname`. The `fileTypeFromBuffer()` result already includes the correct extension derived from the detected MIME type.

## Explanation

The core issue is that the extension is security-relevant: it determines how the stored file is served and whether it can be executed. After validating the file's actual content (magic bytes), the code must use the detected type to derive the extension, not the client-supplied filename.

The file-type library's `detected.ext` is the canonical extension for the detected MIME type (e.g., `'png'` for `image/png`). Using this trusted value instead of `path.extname(req.file.originalname)` ensures that a file's extension always matches its actual content, breaking the attacker's ability to forge a `.php` extension on a PNG payload.

The fix preserves all existing behavior: the same validation runs, the same allowlist is checked, the same UUID is generated for the filename, and the file is still stored in the same location. The only change is that the extension now comes from the detected type instead of the client.

## Behaviour changes

- **File storage**: Instead of `uuid{client-supplied extension}` (e.g., `a1b2c3d4.php` for an uploaded PNG named `image.php`), files are now stored as `uuid.{detected-extension}` (e.g., `a1b2c3d4.png`).
- **Response body**: The JSON response at line 44 now reflects the corrected extension in the `id` field, which is the correct and expected behavior since `storedName` is the actual filename in storage.
- **No functional regression**: All intended upload, validation, and serving behavior remains the same. The API still accepts and stores the same file types, still rejects disallowed types, and still enforces size limits.
