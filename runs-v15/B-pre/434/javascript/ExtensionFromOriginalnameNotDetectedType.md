## Verdict

**Real.** The code validates file content using magic bytes but derives the storage extension from the client-supplied filename, allowing an attacker to choose how the file is served back.

## Source

Line 37: `const clientExt = path.extname(req.file.originalname);`

The client-supplied filename is `req.file.originalname`, which is attacker-controlled metadata from the multipart upload request.

## Fix

Replace lines 37–38:

```javascript
const clientExt = path.extname(req.file.originalname);
const storedName = `${baseName}${clientExt}`;
```

With:

```javascript
const storedName = `${baseName}.${detected.ext}`;
```

The extension now comes from the validated file type (`detected.ext`) rather than from the client's original filename.

## Explanation

The code correctly identifies the file's actual content using magic bytes via `file-type` and validates against an allowlist of permitted MIME types. However, it then uses `path.extname(req.file.originalname)` to determine the storage extension. This allows an attacker to upload a valid PNG file named `shell.php`, which passes the magic-byte validation but gets stored with a `.php` extension. If the file is later served or accessed via any path that respects file extensions (e.g., PHP execution, MIME type sniffing), the attacker-chosen extension determines how the server treats it, bypassing the content validation.

The fix uses the detected file type's extension (`detected.ext` from the `file-type` library result) instead, ensuring the extension always matches the file's actual content type. This breaks the attacker's control over how the stored file will be handled.

## Behaviour changes

- Files are now stored with extensions derived from their detected MIME type, not from client-supplied names.
- A file originally named `image.pdf` but containing actual PNG bytes will be stored as `{uuid}.png` instead of `{uuid}.pdf`.
- All future references to the file will use the detected extension, aligning content handling with actual file type.
