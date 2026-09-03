## Verdict
CWE-434 confirmed. Denylist-based file upload filtering is insufficient; it permits dangerous extensions outside the blocked set and is vulnerable to bypasses.

## Source
Line 22: `return cb(null, true);`

The vulnerability is that the `rejectKnownDangerousExtensions` function approves any file whose extension is not in `BLOCKED_EXTENSIONS`. A denylist permits all unlisted extensions, including dangerous ones like `.phtml`, `.shtml`, `.phar`, `.asp`, `.aspx`, `.jsp`, `.jspx`, and many others depending on the host environment.

## Fix
Replace the denylist with an allowlist. Accept only known-safe file types:

```javascript
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt'];

function rejectDangerousFiles(req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(new Error(`File type ${ext} is not allowed`));
  }
  return cb(null, true);
}

const upload = multer({
  storage,
  fileFilter: rejectDangerousFiles,
});
```

Replace `ALLOWED_EXTENSIONS` with only the file types your application actually needs.

## Explanation
Denylist-based filtering is default-allow: any extension not explicitly blocked is accepted. This is inherently incomplete because:

1. **Hidden dangerous types**: Many extensions can execute code depending on the server configuration (`.phtml`, `.shtml`, `.phar` in PHP; `.aspx`, `.asp` in IIS; `.jsp`, `.jspx` in Java; etc.)
2. **Bypass techniques**: Attackers use double extensions (`.php.jpg`), null bytes, case variations, or directory traversal to evade denylists
3. **Maintenance burden**: New dangerous extensions appear over time, and a denylist that is not continuously updated becomes stale

An allowlist (default-deny) is the correct pattern: only permit extensions the application explicitly expects and needs. Any unlisted extension is rejected immediately, regardless of whether it was anticipated as dangerous.

Additionally, validate the file's MIME type (not just the extension) and consider storing uploads outside the web root and serving them through a download handler that forces them as attachments.
