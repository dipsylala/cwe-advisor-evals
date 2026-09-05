## Verdict

Exploitable. An attacker can upload a file with a client-supplied filename containing path traversal sequences (e.g., `../../evil.png`) or an extension that bypasses content-type validation. More critically, files stored in PUBLIC_DIR (the webroot served by `express.static()`) can execute client-side code—SVG files in the allowlist can embed JavaScript, and files are served directly without protections against execution.

## Source

**Source**: `req.file.originalname` (client-supplied filename from the multipart request)

**Sink**: Line 23, `path.join(PUBLIC_DIR, 'avatars', req.file.originalname)`, where the file is stored using the original client-supplied filename in a directory exposed by `express.static(PUBLIC_DIR)`.

**Data flow**: The multipart upload is received and validated for content type using `fileTypeFromFile()`, which correctly checks actual file bytes against an allowlist. However, the validated filename is never generated—the client-supplied `req.file.originalname` is used directly as the storage path. The file is stored inside PUBLIC_DIR, which is publicly served by `express.static()`.

## Fix

**Vulnerable code:**
```javascript
app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // VULNERABLE: Uses client-supplied originalname in PUBLIC_DIR
  const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + path.basename(destination) });
});
```

**Fixed code:**
```javascript
const crypto = require('crypto');

const app = express();
const upload = multer({ dest: '/tmp/incoming' });

// Store outside PUBLIC_DIR
const PRIVATE_UPLOAD_DIR = path.join(__dirname, 'private', 'uploads');

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml'];

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    // Clean up rejected upload
    await fs.unlink(req.file.path).catch(() => {});
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // Generate random filename with detected extension
  const filename = `${crypto.randomUUID()}.${detected.ext}`;
  const destination = path.join(PRIVATE_UPLOAD_DIR, filename);

  await fs.mkdir(PRIVATE_UPLOAD_DIR, { recursive: true });
  await fs.rename(req.file.path, destination);

  // Store mapping of filename to user/metadata if needed
  res.json({ url: '/avatar/download/' + filename });
});

// Serve avatar downloads through application logic with safe headers
app.get('/avatar/download/:filename', async (req, res) => {
  // Validate filename is UUID format to prevent traversal
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z]+$/.test(req.params.filename)) {
    return res.status(400).json({ error: 'invalid filename' });
  }

  const filepath = path.join(PRIVATE_UPLOAD_DIR, req.params.filename);
  
  // Verify the file exists within PRIVATE_UPLOAD_DIR (prevent traversal)
  const realpath = await fs.realpath(filepath).catch(() => null);
  if (!realpath || !realpath.startsWith(await fs.realpath(PRIVATE_UPLOAD_DIR))) {
    return res.status(404).json({ error: 'not found' });
  }

  // Set headers to prevent script execution
  res.set('Content-Disposition', 'attachment; filename=' + req.params.filename);
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Content-Security-Policy', "default-src 'none'");
  
  res.download(filepath);
});
```

## Explanation

The fix eliminates the vulnerability through three mechanisms. First, it generates a new random filename using `crypto.randomUUID()` instead of trusting the client-supplied `req.file.originalname`, which prevents path traversal attacks (e.g., `../../evil.png`). Second, it derives the file extension from the detected MIME type (`detected.ext`), not the client filename, ensuring the stored file's type is determined by its actual content, not by the attacker. Third, it moves uploads outside PUBLIC_DIR to a private directory incapable of direct web serving; files are returned only through an application-controlled route that validates the filename format, re-verifies the file's realpath to prevent traversal, and sets protective headers (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`) to force downloads instead of in-browser execution. The validation logic also unlinks rejected files to prevent disk space exhaustion. Together, these changes break the taint chain: the attacker no longer controls the stored filename, the file extension, the storage location, or how it is served back.

## Behaviour changes

- **Stored filename**: Changed from client-supplied `originalname` to a random UUID with a validated extension derived from detected type. **Reason**: Prevents path traversal and ensures the file's storage name matches its validated content type.
- **Storage location**: Moved from PUBLIC_DIR (served by express.static) to PRIVATE_UPLOAD_DIR (not publicly accessible). **Reason**: Prevents direct web server access to uploaded files; all access must pass through application logic.
- **File serving**: Added a new `/avatar/download/:filename` route that validates the filename format and realpath before serving. **Reason**: Enforces application-controlled access and prevents directory traversal during download.
- **Response headers on download**: Added `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: default-src 'none'`. **Reason**: Forces download instead of in-browser execution, prevents MIME-type sniffing, and blocks script execution context.
- **Error handling for rejected uploads**: Added `fs.unlink()` to clean up rejected temporary files. **Reason**: Prevents disk exhaustion from repeated malicious uploads and aligns with secure cleanup practices.
- **Filename validation in download route**: Added regex check and realpath verification. **Reason**: Prevents traversal attacks in the download endpoint and validates the filename matches the expected UUID format before filesystem operations.
