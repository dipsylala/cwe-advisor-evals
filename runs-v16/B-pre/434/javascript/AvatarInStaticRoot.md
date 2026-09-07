## Verdict

Exploitable. The application validates file content via MIME type detection but uses the attacker-supplied `req.file.originalname` directly in the storage path. This permits path traversal attacks (e.g., `../../etc/passwd`) and allows the attacker to control the file extension, which determines how the file is served back to clients and accessed by the application.

## Source

`req.file.originalname` (line 23) – the client-supplied filename from the multipart form-data upload request.

## Fix

**Vulnerable code (line 23):**
```javascript
const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);
```

**Fixed code (lines 1 and 23–24):**
```javascript
const crypto = require('crypto');
// ... existing code ...

const destination = path.join(
  PUBLIC_DIR,
  'avatars',
  `${crypto.randomUUID()}.${detected.ext}`
);
```

## Explanation

The fix replaces the attacker-controlled filename with a generated UUID, ensuring each upload receives a unique, unpredictable name that prevents collisions and path traversal attacks. The file extension is now derived from `detected.ext` – the type detected by the `file-type` library during validation (line 16) – rather than from the original filename. This ensures the extension matches the actual file content, not the client's claimed type. Since `file-type` returns both `mime` and `ext` for matched types, `detected.ext` is guaranteed to exist when the MIME check on line 18 passes. The generated name is immune to directory traversal sequences and special characters in the original filename.

## Behaviour changes

The URL returned to the client (line 28) will now reflect the generated UUID rather than the original filename. A client that relied on the server-provided URL to round-trip the original filename will receive a different URL, but this is the intended behaviour: the server controls the storage name, not the client. File downloads will be served with the correct extension derived from the detected type, not the original filename's extension. If the application stores the original filename for user records elsewhere, it must be persisted separately; the current code does not do this, so there is no change in data retention.
