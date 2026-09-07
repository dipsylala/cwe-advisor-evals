## Verdict

EXPLOITABLE

## Source

The source is the attacker-controlled upload received through `request.files["avatar"]` at line 12. The attacker controls:
- The file content (arbitrary bytes)
- The filename via `file.filename` (line 13)
- The Content-Type header via `file.content_type` (line 15)

The data flow: `request.files["avatar"]` → `file.filename` (line 13) and `file.content_type` (line 15) → `os.path.join(UPLOAD_DIR, filename)` (line 16) → `file.save(destination)` (line 18, the sink).

## Fix

```python
from flask import Flask, request
import os
import uuid
import magic
from PIL import Image
import io

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg"}
MIME_TO_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    
    # Read file bytes to detect actual content type
    file_bytes = file.read()
    file.seek(0)  # Reset for later operations
    
    # Detect MIME type from magic bytes
    detected_mime = magic.from_buffer(file_bytes, mime=True)
    
    # Validate detected type against allowlist
    if detected_mime not in ALLOWED_MIME_TYPES:
        return {"status": "rejected"}, 400
    
    # For images, re-encode to strip embedded active content
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()
        # Reopen after verify (which makes the file unusable)
        img = Image.open(io.BytesIO(file_bytes))
        # Re-encode to clean format
        clean_bytes = io.BytesIO()
        img.save(clean_bytes, format=img.format)
        clean_bytes.seek(0)
        file_bytes = clean_bytes.read()
    except Exception:
        return {"status": "rejected"}, 400
    
    # Generate random filename with extension from detected type
    filename = f"{uuid.uuid4()}{MIME_TO_EXT[detected_mime]}"
    destination = os.path.join(UPLOAD_DIR, filename)
    
    # Write cleaned bytes to destination
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with open(destination, "wb") as f:
        f.write(file_bytes)
    
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The original code trusts `file.content_type`, which is a client-supplied header and provides no validation of actual file content. An attacker could send a Python shell or other executable while claiming `Content-Type: image/jpeg`. The original also uses `file.filename` directly, which may contain path traversal sequences or dangerous extensions.

The fix introduces three layers:

1. **Content verification**: `magic.from_buffer(file_bytes, mime=True)` reads the actual file bytes and detects the MIME type from magic bytes (file signature), independent of the client's claim. Only MIME types in the allowlist are accepted.

2. **Content sanitization for images**: `PIL.Image.open()` and re-encoding through `save()` strips embedded active content (scripts in metadata, polyglot payloads). For images, this is stronger than signature checking alone.

3. **Safe storage**: A UUID-generated filename ensures the extension does not come from the attacker. The extension is derived from the detected MIME type via a fixed allowlist map, so what the server will serve the file as is controlled by the server, not the attacker.

The fix also sets `os.makedirs(UPLOAD_DIR, exist_ok=True)` to ensure the upload directory exists before writing, and uses explicit file I/O with `open()` and `write()` instead of Flask's `file.save()` to maintain full control over what bytes hit disk.

## Behaviour changes

- Upload succeeds only if the actual file content matches one of the allowed MIME types (image/png or image/jpeg detected from magic bytes), regardless of the filename extension or Content-Type header.
- Files are stored with a UUID-generated name and a safe extension derived from the detected type, not the original filename. If the original filename is needed for display, store it separately in a database and serve the file through a view that enforces access control.
- Image files are re-encoded, which removes embedded active content (scripts in PNG text chunks, JPEG comments, etc.) but may slightly alter the file (PNG filter optimization, JPEG quality settings during re-encode). This is acceptable for security; if bit-perfect preservation is required, remove the re-encoding and accept that images can only be validated by signature, not content sanitization.
- HTTP responses no longer include the original filename or the upload path in the response body. Clients should retrieve files through a separate lookup or download handler that enforces authorization.
- File size validation is not included in this fix; add `MAX_CONTENT_LENGTH` in Flask config or check `len(file_bytes)` before processing to enforce upload size limits as a defence-in-depth control.
- Requires dependencies: `python-magic`, `Pillow`. These should be added to requirements.txt.
