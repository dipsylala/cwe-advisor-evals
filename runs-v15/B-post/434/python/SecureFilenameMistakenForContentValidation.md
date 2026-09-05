## Verdict

**Finding confirmed and remediable.** The code uses `secure_filename()` to sanitize the filename but performs no validation of the file's actual type or content. This allows upload of executable scripts, web shells, or other dangerous file types. The sink is the `uploaded.save(destination)` call at line 26, which accepts any file that passes filename sanitization.

## Source

Line 14: `uploaded = request.files.get("document")` - attacker-controlled upload source.

Data flows through:
- Line 20: `safe_name = secure_filename(uploaded.filename)` - filename sanitization only, no content validation
- Line 24: `destination = os.path.join(UPLOAD_DIR, safe_name)` - constructs storage path using sanitized filename
- Line 26: `uploaded.save(destination)` - **SINK** - writes file to disk without type validation

## Fix

```python
import os
import uuid
import magic

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"

# Allowlist of permitted MIME types for documents
ALLOWED_TYPES = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
}

# Map MIME types to file extensions
MIME_TO_EXT = {
    'application/pdf': '.pdf',
    'application/msword': '.doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
    'application/vnd.ms-excel': '.xls',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
}


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() strips path separators and unsafe characters from the name only;
    # it does not validate file content. Keep it for display purposes as defence-in-depth.
    safe_display_name = secure_filename(uploaded.filename)
    if not safe_display_name:
        return jsonify({"error": "invalid filename"}), 400

    # Read file bytes and detect actual MIME type using magic bytes, not client-supplied headers
    file_bytes = uploaded.read()
    if not file_bytes:
        return jsonify({"error": "file is empty"}), 400

    detected_type = magic.from_buffer(file_bytes, mime=True)

    # Validate against allowlist of permitted MIME types
    if detected_type not in ALLOWED_TYPES:
        return jsonify({"error": f"file type not allowed: {detected_type}"}), 400

    # Generate a safe storage filename using UUID with extension derived from detected type
    safe_extension = MIME_TO_EXT.get(detected_type, '.bin')
    generated_filename = f"{uuid.uuid4()}{safe_extension}"
    destination = os.path.join(UPLOAD_DIR, generated_filename)

    # Write validated file to storage
    with open(destination, 'wb') as f:
        f.write(file_bytes)

    return jsonify({"status": "stored", "filename": safe_display_name}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix validates the file's actual type by inspecting its magic bytes using `python-magic`, rather than trusting the client-supplied filename extension or Content-Type header. The detected MIME type is checked against an allowlist (`ALLOWED_TYPES`) of permitted document types. Once validated, the file is stored under a server-generated UUID-based filename with an extension derived from the detected type (not the client's original suffix), preventing an attacker from uploading a web shell or executable script by disguising its extension.

The fix preserves `secure_filename()` as a defence-in-depth sanitizer for the display name returned to the client, but the core validation now happens at the content level before any storage operation. The original filename's extension no longer determines what the server will treat the file as.

**New names introduced:**
- `import magic` - from `python-magic` package (external dependency, commonly used for file type detection)
- `import uuid` - standard library, generates random filenames
- `ALLOWED_TYPES` - locally defined set for this application
- `MIME_TO_EXT` - locally defined mapping for this application
- `magic.from_buffer(file_bytes, mime=True)` - API call from python-magic package to detect real MIME type

## Behaviour changes

**Security-relevant changes:**
- Filenames no longer control file type interpretation; magic byte detection does
- Original filename is no longer used for storage, eliminating extension-based bypasses
- Files are stored under random UUIDs, preventing direct prediction of storage paths
- Empty files are rejected before validation

**Functional changes:**
- `uploaded.filename` (original client name) is no longer used as the storage path; it is only returned in the response as `filename` for display purposes
- File bytes are read into memory with `uploaded.read()`, then written with explicit `open()`/`write()` instead of `uploaded.save()`, allowing validation between read and write
- Response includes the detected MIME type in error messages when rejection occurs (not in the 201 response, to avoid leaking type detection logic)
- Rejected files return 400 with a descriptive error; previously, any file that passed `secure_filename()` was accepted
