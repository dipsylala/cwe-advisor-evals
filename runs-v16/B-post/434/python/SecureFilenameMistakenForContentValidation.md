## Verdict

CONFIRMED - CWE-434 (Unrestricted Upload of File with Dangerous Type). The vulnerability is real: `secure_filename()` sanitizes the filename string but performs no validation of file content or type. An attacker can upload a file with malicious content (e.g., PHP shell) using a benign extension (e.g., `.pdf`), and line 26 will save it to disk without inspection.

## Source

**File**: `document_upload.py` lines 11-26  
**Source**: `request.files.get("document")` at line 14 - attacker-controlled multipart upload  
**Taint flow**: `uploaded` object carries both filename and file bytes; filename passes through `secure_filename()` (line 20, sanitization only); file bytes are never inspected before `uploaded.save()` at line 26

## Fix

**Library**: Add `python-magic` to project dependencies (version to be confirmed against SCA/advisory data).

**Vulnerable code** (lines 11-29):
```python
@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() strips path separators and unsafe characters from the
    # name, so this looked like enough sanitization to ship the endpoint.
    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    destination = os.path.join(UPLOAD_DIR, safe_name)
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    uploaded.save(destination)  # <-- No content validation; attacker can upload any file type

    return jsonify({"status": "stored", "filename": safe_name}), 201
```

**Fixed code**:
```python
import os
import uuid

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import magic  # python-magic library

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"

# Allowlist of permitted file types: MIME type -> file extension
ALLOWED_MIME_TYPES = {
    "application/pdf": ".pdf",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
}


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    secure_name = secure_filename(uploaded.filename)
    if not secure_name:
        return jsonify({"error": "invalid filename"}), 400

    # Read file bytes and detect actual MIME type from content (magic bytes)
    file_bytes = uploaded.read()
    uploaded.seek(0)  # Reset file pointer for subsequent save()
    
    detected_mime = magic.from_buffer(file_bytes, mime=True)
    
    # Validate detected type against allowlist
    if detected_mime not in ALLOWED_MIME_TYPES:
        return jsonify({"error": "file type not allowed"}), 400
    
    # Generate new filename: UUID + extension from detected type allowlist
    extension = ALLOWED_MIME_TYPES[detected_mime]
    new_filename = f"{uuid.uuid4()}{extension}"
    destination = os.path.join(UPLOAD_DIR, new_filename)
    
    # Save file with generated name (original filename never used as storage path)
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": secure_name}), 201
```

## Explanation

The fix adds content-based file type validation independent of the filename. Before saving, the code reads file bytes and detects the actual MIME type using `python-magic` (which inspects magic bytes/file signatures), not the client-supplied Content-Type header or filename extension. The detected type is checked against an allowlist of permitted types (PDF, DOCX, etc.); if it does not match, the upload is rejected.

Critically, the storage filename is generated using a UUID and extension derived from the detected type—not from the original filename. This ensures that even if the client uploads a file named `shell.php`, the server stores it as `550e8400-e29b-41d4-a716-446655440000.pdf` (if detected as PDF). The file cannot be executed by the web server because (1) it has no `.php` extension, and (2) it is stored outside the web root under a non-predictable name.

`secure_filename()` is retained as a defence-in-depth sanitizer for the display name returned in the response, but it is no longer the sole validation mechanism.

## Behaviour changes

- **New dependency**: `python-magic` (version TBD from SCA).
- **Rejection**: Uploads with file content not matching the allowlist (e.g., executable scripts uploaded with benign extensions) are now rejected with HTTP 400.
- **Filename change**: Stored filename is now a UUID + extension, not derived from the client's original filename. Display name in response remains the original filename (sanitized).
- **File pointer reset**: After reading bytes to detect type, `uploaded.seek(0)` resets the file pointer so `save()` can read from the start; without this, `save()` would write an empty file.
- **Response unchanged**: HTTP status codes and response format remain the same; only the reject reason changes ("file type not allowed" instead of accepting any file).
