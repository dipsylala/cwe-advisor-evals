## Verdict
The code is vulnerable to CWE-434 (Unrestricted Upload of File with Dangerous Type) at line 23. Although MIME type validation occurs, the filename itself is not validated, allowing path traversal attacks via `req.file.originalname`.

## Source
Line 23 constructs a destination path directly using user-supplied `req.file.originalname`:
```javascript
const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);
```

An attacker can bypass the intended `avatars/` directory by uploading a file with a traversal sequence in the name, such as `../../shell.js` or `..\..\..\evil.exe`, placing the file in an unintended location where it may be executed by the static file server.

## Fix
Replace line 23-28 with filename validation that rejects path traversal patterns:

```javascript
  const sanitized = path.basename(req.file.originalname).replace(/[^a-z0-9._-]/gi, '_');
  if (!sanitized || sanitized === '.') {
    return res.status(400).json({ error: 'invalid filename' });
  }

  const destination = path.join(PUBLIC_DIR, 'avatars', sanitized);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + path.basename(destination) });
```

Alternatively, use a generated filename to avoid trusting user input at all:

```javascript
  const ext = path.extname(req.file.originalname);
  const sanitized = 'avatar_' + crypto.randomBytes(16).toString('hex') + ext;
  const destination = path.join(PUBLIC_DIR, 'avatars', sanitized);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + sanitized });
```

## Explanation
The vulnerability occurs because `req.file.originalname` comes directly from the HTTP request and is used to construct a file path without validation. The `path.join()` method resolves `..` sequences, so a filename like `../../dangerous.js` would traverse up the directory tree regardless of the base path. The `path.basename()` approach removes any directory components, while restricting characters to alphanumeric, dots, hyphens, and underscores. The generated-filename approach avoids trusting user input entirely by constructing a safe name. MIME type validation at line 18-20 confirms the file content is an image, but it does not prevent filename-based attacks. Both fixes ensure files end up only in the intended `avatars/` directory.
