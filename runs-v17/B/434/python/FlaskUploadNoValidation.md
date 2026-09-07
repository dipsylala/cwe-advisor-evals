## Verdict

The finding is correct and exploitable. The upload endpoint accepts file uploads but validates only the client-supplied `Content-Type` header without inspecting actual file content. It also stores files under the original filename, allowing an attacker to upload a web shell (e.g., `shell.php`) or executable script that the server may process or execute. The vulnerability exists at line 18 where `file.save(destination)` writes untrusted, unvalidated bytes to disk.

## Source

Client-supplied file upload via `request.files["avatar"]` (line 12). The attacker controls the filename, file content, and claimed Content-Type header.

## Fix

Replace the unsafe pattern of trusting `file.content_type` and the original filename with:
1. Detect the actual file type by inspecting file content with `python-magic`
2. Validate the detected type against an allowlist
3. Generate a new storage filename using `uuid.uuid4()`
4. Derive the storage extension from a fixed MIME-to-extension map
5. Save the validated file bytes under the generated name

### File: FlaskUploadNoValidation.py

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
    "image/jpeg": ".jpg",
}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    
    # Read file bytes and detect actual MIME type
    file_data = file.read()
    detected_mime = magic.from_buffer(file_data, mime=True)
    
    # Validate against allowlist of MIME types
    if detected_mime not in ALLOWED_MIME_TYPES:
        return {"status": "rejected"}, 400
    
    # Generate new filename with extension from detected type
    file_ext = MIME_TO_EXT[detected_mime]
    new_filename = f"{uuid.uuid4()}{file_ext}"
    destination = os.path.join(UPLOAD_DIR, new_filename)
    
    # Save validated file bytes
    with open(destination, "wb") as f:
        f.write(file_data)
    
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix closes CWE-434 by breaking the trust chain:

**Before**: The code assumed the client-supplied `Content-Type` header (line 15) accurately described the file type, and stored the file under its original filename. An attacker can send `Content-Type: image/jpeg` with a PHP script payload named `shell.php`, bypassing the allowlist check and writing executable code to the webroot.

**After**: The code detects the real file type by reading the actual file bytes with `python-magic.from_buffer()`, which inspects magic bytes/file signatures independent of filename or headers. Only files whose actual content matches an allowlist MIME type are accepted. The storage filename is generated with `uuid.uuid4()` and the extension is derived from a server-controlled map, eliminating the attacker's control over what extension the server will use to serve or execute the file later.

The allowlist `MIME_TO_EXT` map ensures the stored file's extension always matches its actual type. Even if a polyglot file carries a valid PNG header followed by PHP code, the file is stored as `.png`, and if served through proper HTTP headers (`Content-Disposition: attachment`, `Content-Type: image/png`, `X-Content-Type-Options: nosniff`), it will not be executed.

## Behaviour changes

**Storage location**: Files are still written to `UPLOAD_DIR`, unchanged.

**Filename**: The original client-supplied filename is no longer used. Instead, each file is stored under a generated UUID-based name (e.g., `550e8400-e29b-41d4-a716-446655440000.png`). If the application needs to display the original filename to the user, it should store that in a database (not on disk) and serve it through a handler that enforces `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.

**Return value**: The response body still returns `{"status": "ok", "path": destination}` with the same structure, so caller expectations are preserved.

**Memory usage**: The fix reads the entire file into memory with `file.read()` before calling `magic.from_buffer()`. This is necessary for content detection but can be a concern for very large files. For production deployments, consider streaming the file through a temporary location first, detecting its type, validating, then renaming to the final destination if needed for memory constraints.

**Dependencies**: Requires the `python-magic` package (e.g., `pip install python-magic` or `python-magic-bin` on Windows). This must be added to the application's dependency manifest.
