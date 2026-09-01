## Verdict

Exploitable. The code validates only the client-supplied `file.content_type` header, which is easily spoofed. An attacker can upload an executable (`.php`, `.exe`, `.sh`) while claiming `Content-Type: image/png`, and the check passes. The file is then saved under the original filename in the webroot where the server may execute it.

## Source

`request.files["avatar"]` (line 12) - user-supplied multipart form upload, attacker-controlled.

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
    "image/png": "png",
    "image/jpeg": "jpg"
}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    
    # Read file content and detect real MIME type from bytes
    file_data = file.read()
    detected_mime = magic.from_buffer(file_data, mime=True)
    
    # Validate against allowlist using detected type, not client-supplied header
    if detected_mime not in ALLOWED_MIME_TYPES:
        return {"status": "rejected"}, 400
    
    # Generate server-controlled filename; derive extension from detected type
    ext = MIME_TO_EXT[detected_mime]
    safe_filename = f"{uuid.uuid4()}.{ext}"
    destination = os.path.join(UPLOAD_DIR, safe_filename)
    
    # Reset file pointer and save
    file.seek(0)
    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix validates the actual file content using `python-magic` instead of trusting the client-supplied `Content-Type` header. The detected MIME type is checked against an allowlist of permitted types. A server-controlled filename is generated using `uuid.uuid4()`, and the file extension is derived from the detected MIME type through a fixed `MIME_TO_EXT` map, preventing the attacker from choosing the file extension or path. This ensures that an executable disguised with an image header is rejected, and even if the bytes did match an allowed type, the filename and extension would be controlled by the server, not the client. The fix closes the weakness by (1) validating actual content, not headers; (2) removing path and extension control from user input; and (3) breaking taint after allowlist validation by using only the canonical detected MIME type for downstream decisions.

## Behaviour changes

1. **File detection method changes from header to content**: The original code trusts `file.content_type`, which is client-supplied. The fix reads the file bytes and detects the MIME type using `magic.from_buffer()`. Reason: Only content-based detection (magic bytes) reliably identifies file type; headers are client-controlled and spoofable.

2. **Filename changes from original to generated UUID**: The original code uses `file.filename` directly as the storage name. The fix generates a new filename using `uuid.uuid4()` with an extension derived from the detected MIME type. Reason: Prevents path traversal in the original filename, prevents the attacker from choosing the file extension that determines how the server later serves or executes the file, and removes the file-naming decision from user input entirely.

3. **File pointer reset added**: After reading file bytes for magic-byte detection, `file.seek(0)` resets the pointer before `file.save()`. Reason: The `read()` call advances the file pointer; without seeking back to the start, `file.save()` would write a zero-length or partial file.

4. **Extension map added**: A new `MIME_TO_EXT` dictionary maps detected MIME types to canonical extensions. Reason: The stored extension is determined by the server-validated type, not by the original filename suffix, ensuring consistency and preventing mismatches.

