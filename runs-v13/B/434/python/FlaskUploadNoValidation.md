## Verdict

Exploitable. The code validates only the client-supplied `Content-Type` header (line 15), which is not validated file content. An attacker can upload a PHP webshell with a `.png` extension, set the Content-Type header to `image/png`, bypass the weak check, and have the file stored in the webroot (`static/uploads`) with a dangerous extension that the server will execute. The original filename is also used directly as the storage path (line 13), combining extension-based execution risk with filename control.

## Source

- **Input**: `request.files["avatar"]` (line 12) - untrusted file from multipart form
- **Weak validation**: `file.content_type in ALLOWED_CONTENT_TYPES` (line 15) - checks only the client-supplied multipart header, not actual file content
- **Unsafe sink**: `file.save(destination)` (line 18) where destination uses the original filename

## Fix

```python
from flask import Flask, request
from werkzeug.utils import secure_filename
import os
import uuid
from io import BytesIO

app = Flask(__name__)

# Store uploads outside webroot or in secure storage
UPLOAD_DIR = "uploads"

# Allowlist of permitted MIME types (detected from file content, not header)
ALLOWED_MIMETYPES = {"image/png", "image/jpeg"}

# Map detected MIME types to safe file extensions
MIMETYPE_TO_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
}

# Try to import python-magic for robust content detection
try:
    import magic
    def detect_mimetype(content):
        return magic.from_buffer(content, mime=True)
except ImportError:
    # Fallback: use Pillow for image detection
    from PIL import Image
    def detect_mimetype(content):
        try:
            img = Image.open(BytesIO(content))
            return f"image/{img.format.lower()}"
        except Exception:
            return None


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    
    if not file or file.filename == "":
        return {"status": "rejected"}, 400
    
    # Read file bytes for content inspection
    file_content = file.read()
    
    # Detect the actual MIME type from file content (not client-supplied header)
    detected_type = detect_mimetype(file_content)
    
    # Validate detected type against allowlist
    if detected_type not in ALLOWED_MIMETYPES:
        return {"status": "rejected"}, 400
    
    # For images, re-encode to strip embedded scripts and verify format
    if detected_type.startswith("image/"):
        try:
            from PIL import Image
            img = Image.open(BytesIO(file_content))
            img.verify()
            # Re-open (verify() leaves file object unusable) and re-save to strip content
            img = Image.open(BytesIO(file_content))
            output = BytesIO()
            img.save(output, format=img.format)
            file_content = output.getvalue()
        except Exception:
            return {"status": "rejected"}, 400
    
    # Generate a random filename; derive extension from detected MIME type
    # Do not use original filename which is client-controlled
    extension = MIMETYPE_TO_EXT.get(detected_type, ".bin")
    safe_filename = f"{uuid.uuid4()}{extension}"
    
    # Ensure upload directory exists and save outside webroot
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    destination = os.path.join(UPLOAD_DIR, safe_filename)
    
    # Write validated and re-encoded content
    with open(destination, "wb") as f:
        f.write(file_content)
    
    return {"status": "ok", "filename": safe_filename}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix closes CWE-434 by implementing the four core controls from the guidance:

1. **Detect actual file content**: Reads the file bytes and detects the MIME type from magic bytes using `python-magic` (or Pillow as fallback), ignoring the client-supplied `Content-Type` header which is untrusted.

2. **Allowlist validation**: Compares the detected type against `ALLOWED_MIMETYPES`. An attacker cannot bypass this by changing the filename extension or multipart header; the actual bytes are inspected.

3. **Re-encode to strip embedded content**: For images, the code opens and re-saves the file through Pillow, which strips embedded script payloads that might survive a magic-bytes check (e.g., a polyglot PNG carrying embedded JavaScript or PHP).

4. **Generate safe storage filename**: Uses `uuid.uuid4()` to create a randomized filename, ensuring the attacker cannot control the extension or path. The extension is derived from the detected MIME type via the `MIMETYPE_TO_EXT` map, not from the original filename. The file is stored outside the webroot (`uploads/` directory) where it cannot be directly executed by the server, and should be served through application-controlled logic if needed.

The weak check on line 15 (client-supplied `file.content_type`) is replaced with a content-based validation that cannot be spoofed.

## Behaviour changes

- **Rejection of spoofed files**: Files uploaded with mismatched extension and content (e.g., PHP webshell with `.png` name) are now rejected regardless of the Content-Type header.
- **Lost original filename**: The response now returns only the generated `filename`, not a server-controlled path. Applications relying on the original filename for display will need to either store the original name separately in metadata (with caution against XSS on display) or derive a display name from the MIME type.
- **Storage location change**: Files are now stored in an `uploads/` directory outside the webroot rather than `static/uploads/`. Applications serving these files must use a handler endpoint rather than direct static serving, allowing access control enforcement.
- **New dependencies**: The fix requires `python-magic` for robust content detection. Pillow (`PIL`) is used as a fallback for image verification and re-encoding. Both should be added to requirements.
- **Slight performance overhead**: Re-encoding images adds processing time proportional to file size, which is acceptable for the security gain of stripping embedded content.
