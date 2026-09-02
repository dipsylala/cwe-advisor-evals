## Verdict

Exploitable. The code validates file content but stores using the client-supplied filename including extension. An attacker uploads a file with valid image magic bytes but a dangerous extension (e.g., `.js`), passes validation, and is stored as executable in the public directory.

## Source

`req.file.originalname` on line 23. This is user-controlled data from the multipart request and is passed directly to `path.join()` to construct the storage path.

## Fix

```javascript
// Vulnerable code (line 23):
const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);

// Fixed code:
const { randomUUID } = require('crypto');
const destination = path.join(PUBLIC_DIR, 'avatars', `${randomUUID()}.${detected.ext}`);
```

## Explanation

The vulnerability exists because the file extension — which determines how Express serves the file back — comes from the attacker-controlled `req.file.originalname`. Although the code correctly validates the actual file content using `fileTypeFromFile` and checks against an allowlist, this validation is circumvented by using a mismatched extension. An attacker can upload a file with valid PNG bytes but a `.js` extension, pass the content check, and have it stored as executable in the public directory. The fix generates a cryptographically random filename using `crypto.randomUUID()` and derives the extension from the detected MIME type via `detected.ext`, breaking the attacker's control over the extension that determines serving behavior.

## Behaviour changes

The stored filename changes from the user-supplied `originalname` to a UUID-based name with the detected file type's extension (e.g., from `/avatars/photo.js` to `/avatars/550e8400-e29b-41d4-a716-446655440000.png`). This means client code cannot predict or rely on the original filename; the application must return the new URL to the client (which line 28 already does via `path.basename(destination)`). This is a security-required breaking change that prevents the extension-based exploitation path. File size validation via `limits.fileSize` is already in place via multer's `dest` configuration. The file is still served from within the public directory; for additional hardening, consider storing outside `express.static()` and serving through a route handler that sets `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
