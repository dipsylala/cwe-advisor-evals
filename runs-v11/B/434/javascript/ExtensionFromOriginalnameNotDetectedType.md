## Verdict

Real issue confirmed. The code validates file type by inspecting magic bytes (lines 29-32) but derives the storage extension from the client-supplied `req.file.originalname` (lines 37-38), creating a mismatch between actual content and file extension.

## Source

Line 37: `const clientExt = path.extname(req.file.originalname);`

An attacker can upload a valid PNG/JPEG/GIF/PDF file but name it with a dangerous extension (`.php`, `.phtml`, `.exe`). The magic byte validation passes because the content is legitimately allowed, but the stored filename carries the attacker's chosen extension.

## Fix

Replace lines 36-39:

**Current (vulnerable):**
```javascript
const baseName = crypto.randomUUID();
const clientExt = path.extname(req.file.originalname);
const storedName = `${baseName}${clientExt}`;
const destination = path.join(UPLOAD_DIR, storedName);
```

**Fixed:**
```javascript
const baseName = crypto.randomUUID();
const storedExt = detected.ext;
const storedName = `${baseName}.${storedExt}`;
const destination = path.join(UPLOAD_DIR, storedName);
```

The detected object from `fileTypeFromBuffer` (line 30) is already available and contains both `mime` and `ext` fields. Use `detected.ext` for the storage extension instead of extracting it from the client-supplied filename.

## Explanation

The fix ensures the stored filename extension always reflects the actual file type as determined by magic byte inspection, not the client-supplied name. This breaks the attacker's ability to upload a valid image with a `.php` extension and have it stored as a PHP script. Even if the file is later served or accessed based on its extension, the extension will correctly indicate its true type (image, PDF, etc.) rather than an executable type. The generated UUID base name remains securely random, and the corrected extension aligns it with the detected content type.

## Behaviour changes

- Files will now be stored with extensions matching their detected type, not their original filename
- A PNG file uploaded as `malicious.php` will be stored as `{uuid}.png` instead of `{uuid}.php`
- If any code path retrieves and serves files by name (e.g., a download handler using the stored filename), the new extension ensures correct MIME type handling and prevents execution attempts based on file extension
- The storage directory (`UPLOAD_DIR`) remains outside the webroot, providing defence-in-depth regardless of extension handling
