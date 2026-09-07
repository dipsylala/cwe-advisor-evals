## Verdict

The code validates the file's actual MIME type but then uses the client-supplied filename extension instead of the detected extension. This allows an attacker to upload a legitimate image file (e.g., `image.png`) with a dangerous name (e.g., `shell.php`), bypassing extension-based execution controls.

## Source

```javascript
  const baseName = crypto.randomUUID();
  const clientExt = path.extname(req.file.originalname);
  const storedName = `${baseName}${clientExt}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
  await fs.writeFile(destination, req.file.buffer);
```

## Fix

Replace the client-supplied extension with the extension derived from the detected file type:

```javascript
  const baseName = crypto.randomUUID();
  const detectedExt = detected.ext;
  const storedName = `${baseName}.${detectedExt}`;
  const destination = path.join(UPLOAD_DIR, storedName);

  await fs.writeFile(destination, req.file.buffer);
```

## Explanation

The vulnerability exists because the code performs content-based validation (checking the actual file bytes via `fileTypeFromBuffer()`) but then stores the file using the client-supplied filename extension. This creates a gap: a file with genuine image content but a dangerous extension (like `.php`) passes the MIME type check but gets stored with the malicious extension.

The `file-type` library's `detected` object includes the `ext` property, which contains the file extension derived from the actual file's magic bytes. Using `detected.ext` ensures the stored filename extension matches the file's actual type, not the attacker's chosen name. This prevents attacks where an executable extension is used despite the file content being a legitimate image or document.
