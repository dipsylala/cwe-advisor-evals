## Verdict
Confirmed. The code validates file content against a MIME type allowlist but then uses the client-supplied `originalname` extension when storing the file, allowing an attacker to bypass restrictions by uploading a dangerous extension with allowed content (e.g., `malware.exe` containing valid PNG bytes).

## Source
Line 37–38 derive the stored filename from untrusted client input:
```javascript
const clientExt = path.extname(req.file.originalname);
const storedName = `${baseName}${clientExt}`;
```

The detected MIME type (lines 29–34) validates file content but is discarded; only the client-controlled extension influences the stored filename. Line 42 then persists this filename.

## Fix
Map the detected MIME type to a safe extension instead of using `originalname`:

```javascript
const { fileTypeFromBuffer } = await import('file-type');
const detected = await fileTypeFromBuffer(req.file.buffer);

if (!detected || !ALLOWED_MIME_TYPES.has(detected.mime)) {
  return res.status(415).json({ error: 'Unsupported or unrecognized file type' });
}

const mimeToExtension = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/gif': '.gif',
  'application/pdf': '.pdf',
};

const baseName = crypto.randomUUID();
const safeExt = mimeToExtension[detected.mime];
const storedName = `${baseName}${safeExt}`;
const destination = path.join(UPLOAD_DIR, storedName);

await fs.writeFile(destination, req.file.buffer);
```

The extension now derives from the file's detected content type, not the attacker-controlled `originalname`.

## Explanation
The vulnerability exists because the code performs content validation but then discards its result, trusting the client-supplied filename extension instead. An attacker uploads a file with a dangerous extension (`.exe`, `.php`, `.jsp`, etc.) but with content that matches an allowed MIME type. The MIME validation passes, but the dangerous extension persists in storage. A misconfigured web server may then execute the file despite its content being benign.

The fix establishes a deterministic mapping from detected MIME type to extension, ensuring the stored filename can never contain extensions that don't match the actual file content. This defence-in-depth approach prevents both accidental misconfiguration and intentional mismatch attacks.
