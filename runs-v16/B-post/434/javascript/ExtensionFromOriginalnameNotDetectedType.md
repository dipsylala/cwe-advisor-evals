## Verdict

Confirmed exploitable. The code validates file content via magic bytes but stores the file under a client-supplied extension, allowing an attacker to upload a polyglot file (valid image content with injected script) and have it served or executed under a dangerous extension.

## Source

Line 37-38: `const clientExt = path.extname(req.file.originalname);` and `const storedName = `${baseName}${clientExt}`;`

The extension is extracted from the client-supplied filename and used in the stored filename.

## Fix

Replace lines 36-39 with:

```javascript
  const baseName = crypto.randomUUID();
  const storedName = `${baseName}.${detected.ext}`;
  const destination = path.join(UPLOAD_DIR, storedName);
```

Change the extension from `path.extname(req.file.originalname)` to `detected.ext`, which comes from the `file-type` library's detection result and reflects the actual validated content type, not the client-supplied filename.

## Explanation

The code correctly validates the file's actual bytes using `fileTypeFromBuffer()` against an allowlist (lines 30-34), which is the primary defense. However, it undermines this protection by storing the file under the client-supplied extension from `originalname`. An attacker can craft a polyglot file—for example, a valid PNG (passing the magic byte check) with embedded JavaScript—and name it `shell.php`. The file passes content validation but is stored as `{uuid}.php` and can later be executed as PHP code, defeating the content check.

The fix substitutes the detected file extension (`detected.ext` from the `file-type` result) for the client-supplied one. This ensures the stored filename's extension always matches the validated content type, so a PNG stored as `{uuid}.png` cannot be executed as code even if the attacker supplied a `.php` extension in the original request.

## Behaviour changes

- File extensions in storage now reflect detected type, not client-supplied names.
- Files with forged extensions but valid content for a different type are stored safely (e.g., a `.php` file with valid PNG content becomes `.png` on disk).
- Any downstream code serving files from `UPLOAD_DIR` via file extension lookup will now use the correct safe extension; no changes needed there as long as serving is not performed through direct `express.static()` access.
