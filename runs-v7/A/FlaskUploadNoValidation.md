## Verdict
Vulnerable. CWE-434 occurs because the code trusts the `content_type` header, which is spoofable, and does not validate the file extension or verify actual file content.

## Source
```python
file = request.files["avatar"]
filename = file.filename

if file.content_type in ALLOWED_CONTENT_TYPES:
    destination = os.path.join(UPLOAD_DIR, filename)
    file.save(destination)  # Line 18: Sink
```

The vulnerability exists at line 18 (`file.save(destination)`), reached when `content_type` matches the allowlist. An attacker can:
- Spoof the content-type header to bypass the MIME check
- Upload a file with a dangerous extension (e.g., `.php`, `.exe`, `.sh`)
- Use a crafted filename to traverse directories via `os.path.join`

## Fix
```python
from flask import Flask, request
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}

def is_image_magic_bytes(data, expected_type):
    """Verify file magic bytes match the claimed type."""
    if expected_type == "image/png":
        return data[:8] == b'\x89PNG\r\n\x1a\n'
    elif expected_type in ("image/jpeg", "image/jpg"):
        return data[:2] == b'\xff\xd8'
    return False

@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    filename = file.filename
    
    if not filename:
        return {"status": "rejected"}, 400
    
    # Validate extension against allowlist
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return {"status": "rejected"}, 400
    
    # Check content-type (defense-in-depth, not primary check)
    if file.content_type not in {"image/png", "image/jpeg"}:
        return {"status": "rejected"}, 400
    
    # Verify actual file content via magic bytes
    file_data = file.read()
    file.seek(0)
    if not is_image_magic_bytes(file_data, file.content_type):
        return {"status": "rejected"}, 400
    
    # Sanitize filename and prevent directory traversal
    safe_name = secure_filename(filename)
    destination = os.path.join(UPLOAD_DIR, safe_name)
    file.save(destination)
    return {"status": "ok", "path": destination}, 200

if __name__ == "__main__":
    app.run()
```

## Explanation
The fix addresses CWE-434 through defense-in-depth:

1. **Extension whitelist (primary defense)**: Check the file extension against `ALLOWED_EXTENSIONS` before any upload logic. This stops common vectors like `.php`, `.exe`, `.jsp`.

2. **Magic bytes verification**: Verify the actual file content using magic bytes (file signatures). Content-Type headers are spoofable; magic bytes come from the file itself. The `is_image_magic_bytes()` function confirms PNG and JPEG files by their binary signatures.

3. **Filename sanitization**: `secure_filename()` removes path separators and dangerous characters, preventing directory traversal attacks (e.g., `../../etc/passwd`).

4. **Content-Type check (secondary)**: Keep the original content-type check as a second layer, but acknowledge it is not sufficient alone since headers are user-controlled.

5. **Read and rewind**: `file.read()` fetches the content for magic-byte validation, and `file.seek(0)` resets the pointer before `file.save()`, ensuring the full file is written.

The extension whitelist is the primary control; magic-byte verification provides defense-in-depth to catch spoofed uploads; `secure_filename()` prevents traversal.
