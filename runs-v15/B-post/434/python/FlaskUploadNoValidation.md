## Verdict

The code accepts uploads based on `file.content_type` header (client-supplied and untrustworthy) and saves with the original filename into a web-accessible directory. Neither the client's claimed type nor the filename is validated against actual content. An attacker can upload a malicious executable (shell.php, shell.asp, evil.phtml) with a spoofed image content-type and execute it through the web server.

## Source

```python
file = request.files["avatar"]
filename = file.filename

if file.content_type in ALLOWED_CONTENT_TYPES:
    destination = os.path.join(UPLOAD_DIR, filename)
    file.save(destination)
```

Lines 12-18 receive an upload, check only the client-supplied header, and save it to a predictable path using the original filename inside the webroot.

## Fix

```python
from flask import Flask, request
import os
import uuid
from PIL import Image
from io import BytesIO

app = Flask(__name__)

UPLOAD_DIR = os.path.abspath("uploads")  # Outside webroot
MIME_TO_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    
    # Validate file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_FILE_SIZE:
        return {"status": "rejected", "reason": "File too large"}, 400
    
    # Read file bytes to detect actual content
    file_data = file.read()
    file.seek(0)
    
    # Validate by attempting to open as image and re-encoding
    try:
        img = Image.open(BytesIO(file_data))
        img.verify()
        
        # Reopen after verify (which closes the file object)
        img = Image.open(BytesIO(file_data))
        
        # Determine MIME type from image format
        detected_format = img.format.lower()
        if detected_format == "jpeg":
            mime_type = "image/jpeg"
        elif detected_format == "png":
            mime_type = "image/png"
        else:
            return {"status": "rejected", "reason": "Unsupported image format"}, 400
        
        # Check against allowlist
        if mime_type not in MIME_TO_EXT:
            return {"status": "rejected", "reason": "Type not allowed"}, 400
        
        # Generate safe filename with extension derived from detected type
        filename = str(uuid.uuid4()) + MIME_TO_EXT[mime_type]
        destination = os.path.join(UPLOAD_DIR, filename)
        
        # Ensure upload directory exists
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        # Re-encode through Pillow to strip embedded active content
        img.save(destination)
        
        return {"status": "ok", "path": destination}, 200
    
    except Exception as e:
        return {"status": "rejected", "reason": "Invalid image"}, 400


if __name__ == "__main__":
    app.run()
```

## Explanation

**Root cause:** The code trusts `file.content_type` (client-supplied HTTP header) and the original filename without inspecting actual file bytes. An attacker sends a PHP shell with `Content-Type: image/png`, bypasses the header check, and the server saves it into the webroot with a `.php` extension where the web server executes it.

**Defense strategy:**
1. **Detect real content:** Use Pillow's `Image.open()` and `verify()` to confirm the bytes actually parse as a valid image, rejecting polyglots and malformed payloads.
2. **Generate safe filename:** Use `uuid.uuid4()` for the storage name so the attacker cannot control the path or extension.
3. **Derive extension from type:** Map the detected MIME type (confirmed by Pillow, not by headers) to a whitelisted extension, so the stored file's content type matches its extension.
4. **Store outside webroot:** Save to `uploads/` (outside `static/`) so direct web requests to `/uploads/file.png` do not serve files. Serve only through a handler that enforces access control.
5. **Re-encode images:** Pillow's `save()` re-encodes the image, stripping embedded scripts and polyglot payloads that might survive format verification.
6. **Enforce size limits:** Bound uploaded file size to prevent resource exhaustion.

**Why the original fix fails:**
- `secure_filename()` sanitizes path traversal characters but says nothing about content or type.
- `file.content_type` comes from the client's request headers and is not validated.
- Storing with the original filename lets the attacker control the extension, so `malicious.php` with a spoofed type bypasses the check and executes.
- The `static/uploads` directory is web-accessible, so any executable file (PHP, ASP, JSP, PHTML) saved there is immediately executable.

## Behaviour changes

**Before:** Any file with a spoofed `image/png` or `image/jpeg` header is accepted and saved to the webroot with its original name, allowing code execution.

**After:**
- Only valid PNG and JPEG files (verified by Pillow) are accepted; all other formats, polyglots, and corrupted images are rejected.
- Files are stored outside the webroot under a server-generated UUID name with an extension derived from the detected MIME type, not the client's claim.
- Image data is re-encoded during save, removing embedded active content.
- File size is limited to prevent resource exhaustion.
- An attacker cannot control the stored filename or execute arbitrary code, even with a spoofed content-type header.
