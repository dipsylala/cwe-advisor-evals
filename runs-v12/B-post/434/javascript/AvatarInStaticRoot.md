## Verdict

Exploitable. The code trusts `req.file.originalname` to construct the file path, enabling two attack chains: path traversal (e.g., `../../../evil.js`) and extension manipulation. Although the code validates the file's MIME type by inspecting magic bytes, the stored extension—which determines how the server later serves the file—comes from client input, not from the validated detection result. The file is stored inside the webroot served by `express.static`, where an executable file matching the attacker's chosen extension can be executed.

## Source

`req.file.originalname` — the client-supplied filename from the multipart upload request. This value is untrusted and attacker-controlled.

## Fix

**Vulnerable code (line 23):**
```javascript
  const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);
```

**Fixed code:**
```javascript
const crypto = require('crypto');

// ... in the route handler, after the type check (line 20) and before line 25:

  const filename = `${crypto.randomUUID()}.${detected.ext}`;
  const destination = path.join(PUBLIC_DIR, 'avatars', filename);
```

The fixed code requires adding `const crypto = require('crypto');` at the top of the file, alongside the existing imports.

## Explanation

The fix replaces the client-supplied `req.file.originalname` with a server-generated filename constructed from `crypto.randomUUID()` and the safe extension provided by the `file-type` library's detection result (`detected.ext`). This eliminates path traversal risk—the generated UUID cannot contain `../` sequences—and ensures the file extension comes from the validated MIME type, not client input. The storage location remains inside the webroot, but the random name and guaranteed-safe extension prevent the attacker from choosing whether the file is executable or which path components are traversable. The file is then served via the response URL using the same safe filename, so the client receives a predictable but unpredictable-to-the-attacker reference.

For production systems, consider storing uploads outside the webroot entirely to prevent execution risk regardless of extension; that would require an additional route handler to stream the file back from private storage.

## Behaviour changes

- **Adds import**: `const crypto = require('crypto')` is required.
- **Filename changes**: The stored file is now named `<uuid>.<extension>` (e.g., `550e8400-e29b-41d4-a716-446655440000.png`) instead of the original client-supplied name. This is a breaking change for any client that expects to retrieve the file by its original name—the server no longer has that information and cannot reverse the mapping.
- **Response URL changes**: Line 28's response URL changes from `/avatars/original-name.png` to `/avatars/<generated-uuid>.png`. Any client expecting the original filename in the response must be updated to use the returned URL instead.
- **File extension source**: The extension is now bound to the validated MIME type rather than client input. A file with MIME type `image/png` will always be stored with a `.png` extension, regardless of what the client supplied in the filename.
