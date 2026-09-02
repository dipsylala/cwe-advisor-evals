## Verdict

Exploitable. The code trusts the client-supplied `Content-Type` header without validating actual file content, and uses the original untrusted filename for storage. An attacker can upload executable content with a spoofed MIME type and filename, leading to remote code execution if the webroot is writable.

## Source

User-uploaded file via `request.files["avatar"]` (line 12) and its properties `file.content_type` (line 15) and `file.filename` (line 13).

## Fix

**Vulnerable code:**
```python
@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    filename = file.filename

    if file.content_type in ALLOWED_CONTENT_TYPES:
        destination = os.path.join(UPLOAD_DIR, filename)
        # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
        file.save(destination)
        return {"status": "ok", "path": destination}, 200

    return {"status": "rejected"}, 400
```

**Fixed code:**
```python
from flask import Flask, request
import os
import uuid
import magic

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg"}
MIME_TO_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg"
}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    
    if not file:
        return {"status": "rejected"}, 400
    
    # Read file content to validate actual type
    file_content = file.read()
    file.seek(0)  # Reset file pointer for save()
    
    # Detect real MIME type from file content, not client header
    detected_mime = magic.from_buffer(file_content, mime=True)
    
    if detected_mime not in ALLOWED_MIME_TYPES:
        return {"status": "rejected"}, 400
    
    # Generate filename from detected type, never use client-supplied name
    extension = MIME_TO_EXT.get(detected_mime, "")
    if not extension:
        return {"status": "rejected"}, 400
    
    filename = str(uuid.uuid4()) + extension
    destination = os.path.join(UPLOAD_DIR, filename)
    
    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix replaces client-supplied validation with content-based validation using `python-magic`. Instead of trusting the `Content-Type` header, the code now reads the file bytes and detects the real MIME type via magic bytes. The filename is generated using `uuid.uuid4()` with an extension derived from the detected MIME type through an allowlist map (`MIME_TO_EXT`), preventing both filename-based attacks and type confusion. The original client filename is never used, eliminating path traversal and double-extension attack vectors. Three rejection points guard the sink: missing file, disallowed MIME type, and unmapped extension.

## Behaviour changes

- **Requires new dependency**: `python-magic` must be installed (`pip install python-magic`) for `magic.from_buffer()` to work. This is a runtime requirement for the fix to function.
- **File read before save**: The code now reads the entire file into memory via `file.read()` and `file.seek(0)` to enable magic-byte inspection. For large uploads, this increases memory usage proportionally. The file pointer is reset before `file.save()` so the save operation receives the full content.
- **Response path change**: The endpoint now returns status 400 for files with disallowed MIME types (detected via content) or missing extension mappings, whereas the original code would only reject based on the spoofable `Content-Type` header. This closes the vulnerability but may reject uploads that passed the old check if their real content type differs from the claimed type.
- **Filename is always server-generated**: The original filename is never used or returned in the response path; the response still returns the stored `destination` path (which now contains the UUID) instead of the original client filename. Applications depending on retrieving the original filename must be updated to store it separately if needed for user-facing references.
