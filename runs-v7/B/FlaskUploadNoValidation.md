## Verdict

Exploitable. The code accepts an untrusted filename directly from `file.filename` without sanitization and relies on `file.content_type` (client-supplied header) for type validation. An attacker can bypass the content-type check by spoofing the header and upload a file with a malicious filename such as `../../../shell.php` or `evil.exe`, exploiting the lack of filename sanitization and content validation.

## Source

`request.files["avatar"]` receives the user-supplied file from the multipart upload request. The filename (`file.filename`) and content-type header are both attacker-controlled.

## Fix

**Vulnerable Code:**
```python
file = request.files["avatar"]
filename = file.filename

if file.content_type in ALLOWED_CONTENT_TYPES:
    destination = os.path.join(UPLOAD_DIR, filename)
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    file.save(destination)
    return {"status": "ok", "path": destination}, 200
```

**Fixed Code:**
```python
from flask import Flask, request
import os
from werkzeug.utils import secure_filename
import magic
import uuid

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg"}

# Mapping from detected MIME type to safe extension
MIME_TO_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
}

@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    
    # Read file content to validate actual type (not just header)
    file_content = file.read()
    file.seek(0)  # Reset file pointer for save
    
    # Detect real MIME type from file bytes (magic bytes)
    detected_mime = magic.from_buffer(file_content, mime=True)
    
    # Validate against allowlist of actual detected types
    if detected_mime not in ALLOWED_CONTENT_TYPES:
        return {"status": "rejected"}, 400
    
    # Derive extension from detected MIME type, not client filename
    safe_extension = MIME_TO_EXT.get(detected_mime, ".bin")
    
    # Generate safe filename using UUID to prevent path traversal and extension attacks
    safe_filename = f"{uuid.uuid4()}{safe_extension}"
    destination = os.path.join(UPLOAD_DIR, safe_filename)
    
    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix addresses the vulnerability by implementing three key changes. First, it reads the actual file bytes and validates the real MIME type using `python-magic` (not the client-supplied `content_type` header), checking it against an allowlist of allowed types. Second, it generates a new filename using `uuid.uuid4()` and derives the extension from the detected MIME type through a fixed allowlist map, eliminating the use of the original untrusted filename that could contain path traversal sequences like `../` or `..\\`. Third, the generated filename eliminates the ability for an attacker to influence the file extension—even if they upload `shell.php` with a spoofed PNG content-type, the saved file will be named something like `a1b2c3d4-e5f6-4g7h-8i9j-0k1l2m3n4o5p.png`. This ensures that path traversal attacks and extension-based execution attacks are blocked at the point the file reaches the sink.

## Behaviour changes

- **Imports added**: `secure_filename` (defense-in-depth, future use), `magic` (required for content validation), and `uuid` (for generating safe filenames). Note: `python-magic` must be added as a dependency (install via `pip install python-magic` or `python-magic-bin` on Windows).
- **New module-level constant**: `MIME_TO_EXT` maps detected MIME types to safe extensions, derived from the detected type rather than client input.
- **File reading**: `file.read()` is called before `file.save()` to inspect content; `file.seek(0)` resets the file pointer so `save()` reads from the beginning. This adds I/O but is necessary for content validation.
- **Return value unchanged**: Still returns `{"status": "ok", "path": destination}` and HTTP 200 on success, or `{"status": "rejected"}` and HTTP 400 on type mismatch. The path now reflects the server-generated filename, not the client-supplied one.
- **File saved with generated name**: The sink (`file.save()`) now receives a safe, server-controlled path derived from UUID + detected extension, not the original filename. An attacker cannot influence the storage location or extension.
