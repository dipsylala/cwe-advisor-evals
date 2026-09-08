## Verdict

**CONFIRMED EXPLOITABLE**

The upload endpoint trusts `secure_filename()` to validate file type, but it only sanitizes the filename string. The actual file content is never validated. An attacker can upload a malicious executable (PHP, JSP, Python, etc.) with a spoofed extension, and it will be saved to `UPLOAD_DIR` under the attacker's chosen name. If `UPLOAD_DIR` is served by a web server, the shell becomes executable.

## Source

**File:** `document_upload.py`

**Entry point:** `request.files.get("document")` at line 14 — attacker-controlled file upload

**Data flow:**
- Line 14: `uploaded = request.files.get("document")` — raw, untrusted file object
- Line 20: `safe_name = secure_filename(uploaded.filename)` — sanitizes only the filename string; no content validation
- Line 24: `destination = os.path.join(UPLOAD_DIR, safe_name)` — constructs storage path using client-supplied name
- Line 26: `uploaded.save(destination)` — **SINK** — writes file without content validation

**Weakness:** The code assumes `secure_filename()` validates file type, but it only removes path separators and unsafe characters from the filename. The actual file bytes are never inspected.

## Fix

**New dependency:** `python-magic` — used to detect file type from actual bytes, not filename or client-supplied Content-Type header.

### File: document_upload.py

```python
import os
import uuid

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import magic

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"

# Allowlist of permitted MIME types and their safe extensions
ALLOWED_MIME_TYPES = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "text/plain": ".txt",
}


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() sanitizes the filename string only; it performs no content
    # or type validation. Always pair it with a separate content check.
    display_name = secure_filename(uploaded.filename)
    if not display_name:
        return jsonify({"error": "invalid filename"}), 400

    # Read file bytes and detect the real MIME type from content
    file_bytes = uploaded.read()
    detected_mime = magic.from_buffer(file_bytes, mime=True)

    # Validate the detected type against an allowlist
    if detected_mime not in ALLOWED_MIME_TYPES:
        return jsonify({"error": "file type not allowed"}), 400

    # Generate a new filename using the detected type's safe extension
    extension = ALLOWED_MIME_TYPES[detected_mime]
    generated_filename = f"{uuid.uuid4()}{extension}"
    destination = os.path.join(UPLOAD_DIR, generated_filename)

    # Reset the stream position before saving
    uploaded.seek(0)
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": generated_filename}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix applies three layers of defence:

1. **Content validation (primary):** Line 36 reads the actual file bytes and line 37 detects the real MIME type using `magic.from_buffer()`. This inspects the file's magic bytes (the binary signature at the start of the file) rather than trusting the filename extension or client-supplied `Content-Type` header. Line 40 enforces an allowlist of permitted types, rejecting anything not explicitly permitted.

2. **Filename generation and taint break:** Line 45 generates a new filename using `uuid.uuid4()` and the extension derived from the detected MIME type (line 44), not the client-supplied name. This ensures that even if an attacker uploads a file named `shell.php`, it is stored as something like `a1b2c3d4-e5f6-4g7h-8i9j-k0l1m2n3o4p5.pdf`. The generated filename is returned to the client (line 50), not the original; the server has complete control over how the stored file is served.

3. **Sanitization as defence-in-depth:** Line 33 still applies `secure_filename()` to the original filename for display purposes and to prevent path traversal in the unlikely event the original name is logged or used elsewhere. This is no longer the primary defence, but it remains as a secondary check.

The file is stored under a generated name in `UPLOAD_DIR` (whose actual web-serving configuration is outside this code). If `UPLOAD_DIR` is configured as a static-serving directory, the stored file will be served with the MIME type derived from its extension (which now matches its actual content), not the attacker's original choice.

## Behaviour changes

- **Storage path:** Changed from `UPLOAD_DIR/{client_supplied_name}` to `UPLOAD_DIR/{uuid}.{detected_ext}` — the attacker no longer controls the filename or extension
- **Response filename:** Changed from `safe_name` (sanitized original) to `generated_filename` (uuid-based) — the client receives the server-generated name, not the original
- **Validation:** New check at line 40 rejects files whose detected MIME type is not in `ALLOWED_MIME_TYPES` — attempting to upload a shell will return 400 even if given a PDF extension
- **File reading:** The file is read into memory at line 35 to detect its type, then re-wound at line 48 before saving — the overall operation is identical from the Flask upload object's perspective, but the bytes are now inspected
- **New dependencies:** Requires `python-magic` package to be installed; `uuid` and `os` are standard library
- **Upload size:** No explicit size limit is added in this fix, but the code will read the entire file into memory for magic-byte detection — large uploads may cause memory pressure; consider pairing this with Flask's `MAX_CONTENT_LENGTH` configuration as a secondary hardening measure
