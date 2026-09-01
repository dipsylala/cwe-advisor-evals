## Verdict

**EXPLOITABLE** - The code validates the file content with magic bytes but uses the client-supplied `req.file.originalname` to determine the storage path and filename. An attacker can upload a valid image with a dangerous extension (e.g., `.exe`, `.jsp`, `.html`) or traverse the directory structure to escape the intended storage location.

## Source

`req.file.originalname` - the filename from the multipart upload request (attacker-controlled).

## Fix

Replace line 23 to generate a cryptographically random filename and derive its extension from the validated file type, not the original filename:

**Vulnerable code (line 23):**
```javascript
const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);
```

**Fixed code:**
```javascript
const crypto = require('crypto');
// ... (add at top of file if not already present)

// Line 23 replacement:
const destination = path.join(PUBLIC_DIR, 'avatars', `${crypto.randomUUID()}.${detected.ext}`);
```

## Explanation

The fix generates a new filename using `crypto.randomUUID()` instead of trusting the attacker-controlled `originalname`. Critically, the extension is derived from `detected.ext` (the MIME type detected by `file-type`), not from the original filename. This prevents an attacker from uploading a valid PNG with a `.exe` extension and having it served as executable despite passing the content validation. The random UUID also prevents directory traversal via path sequences and filename collisions. The `detected.ext` value is guaranteed to match the validated MIME type (from the allowlist check on line 18), so the extension is now controlled by the server's type allowlist, not the client.

## Behaviour changes

- **New dependency**: Requires the Node.js built-in `crypto` module (no additional package needed).
- **Filename format**: Uploaded files are now stored as UUIDs with validated extensions (e.g., `a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d.png`) instead of original names.
- **URL generation**: The returned avatar URL now reflects the generated filename rather than the original upload name.
- **No functional impact on validation**: The security validation (magic bytes check) remains unchanged; only the storage path generation is hardened.
