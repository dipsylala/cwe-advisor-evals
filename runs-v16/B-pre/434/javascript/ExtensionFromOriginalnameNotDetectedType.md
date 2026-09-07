## Verdict
exploitable

## Source
Line 37: `req.file.originalname` (client-supplied filename from the multipart upload request)

## Fix

**Vulnerable code (lines 37-38):**
```javascript
const clientExt = path.extname(req.file.originalname);
const storedName = `${baseName}${clientExt}`;
```

**Fixed code:**
```javascript
const storedExt = detected.ext;
const storedName = `${baseName}.${storedExt}`;
```

## Explanation
The vulnerability occurs because the extension used in the storage filename is derived from the client-supplied `originalname` field rather than from the detected file type. Although the code validates the file's actual content (via `file-type` magic bytes on lines 29-32), the extension that determines how the file is served comes from untrusted client input. This allows an attacker to upload a valid image file but claim it is a `.php` or `.exe` in the original filename; the stored file will preserve the malicious extension despite content validation. By deriving the extension from `detected.ext` (the mime-type detection result), the stored filename reflects the actual content type and prevents extension spoofing. The `file-type` library returns an `ext` property that safely maps the detected MIME type to an appropriate extension.

## Behaviour changes
none
