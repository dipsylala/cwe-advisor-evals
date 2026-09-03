## Verdict

The vulnerability exists at line 23. The code uses the user-supplied filename (`req.file.originalname`) directly in the destination path without sanitization, allowing a file with a dangerous or path-traversal filename to be written to the static-served directory.

## Source

Line 23: `const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);`

The filename originates from `req.file.originalname`, a value controlled entirely by the client during upload.

## Fix

Generate a safe filename instead of using the original:

```javascript
const { randomUUID } = require('crypto');
// ... in the route handler ...
const ext = detected.mime === 'image/png' ? '.png' : detected.mime === 'image/jpeg' ? '.jpg' : '.svg';
const destination = path.join(PUBLIC_DIR, 'avatars', randomUUID() + ext);
```

Alternatively, if the original filename must be preserved for UX, strip all path separators and special characters:

```javascript
const safeName = req.file.originalname.replace(/[\/\\]/g, '').replace(/[^\w.-]/g, '_');
const destination = path.join(PUBLIC_DIR, 'avatars', safeName);
```

The first approach (UUID-based) is preferred because it is immune to filename-based attacks and collision.

## Explanation

CWE-434 manifests when a file is uploaded to a web-accessible location without restricting the filename to safe values. Although this code validates the file content via MIME type, it does not validate the filename. An attacker can upload a file with a name like `shell.php`, `../../../etc/passwd`, or `.htaccess` to potentially:

1. Execute server-side code if the static directory serves executable types
2. Perform path traversal to write files outside the intended directory
3. Overwrite configuration files

Generating a cryptographically random UUID as the filename eliminates the filename as an attack vector entirely, while preserving the correct file extension based on detected MIME type ensures the resource is still served correctly.
