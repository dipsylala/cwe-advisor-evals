## Verdict

**VULNERABLE** — CWE-434: Unrestricted Upload of File with Dangerous Type

The code at line 18 (`file.save(destination)`) stores an uploaded file after validating only the client-supplied `Content-Type` header and using the original filename for storage. Both are unsafe: `file.content_type` is untrustworthy client input, and the original filename determines the extension, allowing an attacker to upload a web shell disguised as an image (e.g., `shell.php` with `Content-Type: image/png`). The file is stored in the webroot (`static/uploads`) under its original name, making it directly executable if the server handler recognizes the extension.

## Source

**File:** `evals/cases/434/python/FlaskUploadNoValidation/FlaskUploadNoValidation.py`  
**Line:** 18  
**Sink:** `file.save(destination)`

**Data flow:**
- Line 12: Attacker-controlled file received via `request.files["avatar"]`
- Line 13: Original filename extracted (`file.filename`)
- Line 15: Insufficient validation using client-supplied `file.content_type` only
- Line 16: Storage path constructed using original filename
- Line 18: File written to disk with extension controlled by attacker

## Fix

```python
from flask import Flask, request
import os
import uuid
import magic
from PIL import Image
from io import BytesIO

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
    
    # Read file bytes
    file_bytes = file.read()
    file.seek(0)  # Reset for potential re-read
    
    # Detect real MIME type from bytes using python-magic
    detected_type = magic.from_buffer(file_bytes, mime=True)
    
    # Validate against allowlist of real types
    if detected_type not in ALLOWED_MIME_TYPES:
        return {"status": "rejected"}, 400
    
    # For images, re-encode to strip embedded active content
    if detected_type.startswith("image/"):
        try:
            img = Image.open(BytesIO(file_bytes))
            img.verify()
            # Re-encode to remove potential payload
            img = Image.open(BytesIO(file_bytes))
            encoded_buffer = BytesIO()
            img.save(encoded_buffer, format=img.format)
            file_bytes = encoded_buffer.getvalue()
        except Exception:
            return {"status": "rejected"}, 400
    
    # Generate new filename with extension derived from detected type
    extension = MIME_TO_EXT.get(detected_type, ".bin")
    new_filename = f"{uuid.uuid4()}{extension}"
    destination = os.path.join(UPLOAD_DIR, new_filename)
    
    # Save file with server-generated name
    with open(destination, "wb") as f:
        f.write(file_bytes)
    
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix implements the four core defenses for CWE-434:

1. **Validate actual content with python-magic** (line 28): Read the file bytes and detect the MIME type using `magic.from_buffer()`, which inspects the file's magic bytes/signature rather than trusting the client-supplied `Content-Type` header. This defeats spoofed content-type claims (e.g., `shell.php` claimed as `image/png`).

2. **Enforce allowlist on detected type** (line 31–32): Check the detected type against `ALLOWED_MIME_TYPES`, not the client input. This prevents uploading dangerous types regardless of how they are named or claimed.

3. **Generate new filename with mapped extension** (line 44–46): Use `uuid.uuid4()` to create a server-controlled filename and derive the extension from a fixed `MIME_TO_EXT` allowlist. This removes the attacker's ability to choose the file extension, preventing execution if the server would serve `static/uploads/*.php` as a script.

4. **Re-encode images to strip embedded content** (line 34–42): For image types, use PIL to open, verify, and re-save the image. This re-encoding process strips any embedded scripts or polyglot payloads that might pass a signature check.

The stored filename is now under the server's control, not the attacker's, eliminating the path traversal and extension-override vectors.

## Behaviour changes

- **Before:** Application accepts any file with `Content-Type: image/png` or `image/jpeg` in the request header, stores it with the original filename in the webroot, allowing an attacker to upload `shell.php` (with spoofed content-type) and execute it.

- **After:** Application reads file bytes, detects the real MIME type from content, rejects files that do not match the allowlist, re-encodes images to strip embedded content, and stores the file under a server-generated UUID filename with an extension derived from the detected type. An attacker cannot upload a web shell or control the storage path or extension. Requests for `/profile/avatar` with a file whose bytes do not match `image/png` or `image/jpeg` return `HTTP 400 (rejected)`.
