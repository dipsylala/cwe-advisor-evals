## Verdict

**Confirmed vulnerability.**

`secure_filename()` performs filename sanitization only (stripping path separators and unsafe characters). It does not validate file type or content. The code assumes sanitization of the filename string is sufficient, but an attacker can upload a dangerous file type (e.g., PHP shell, executable, script) and it will be written to disk. The sink at line 26 (`uploaded.save(destination)`) persists the unvalidated file.

## Source

The vulnerable code receives an uploaded file at line 14, applies only `secure_filename()` at line 20 (which sanitizes the name string but not content), and saves the file at line 26 without any type validation.

Data flows from `request.files.get("document")` → `secure_filename(uploaded.filename)` → `uploaded.save(destination)`. The security gap is between the filename sanitization and the save: actual file content is never checked.

## Fix

### File: document_upload.py

```python
import os
import uuid

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import magic

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"

# Allowlist of permitted MIME types with their safe extensions
PERMITTED_TYPES = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/msword": ".doc",
    "text/plain": ".txt",
}


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() only sanitizes the filename string; it does not validate content or type.
    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    # Read file bytes to detect real type from content, not from extension or client-supplied MIME type.
    file_bytes = uploaded.read()
    if not file_bytes:
        return jsonify({"error": "empty file"}), 400

    # Detect the actual MIME type using magic bytes, independent of the filename extension.
    detected_mime = magic.from_buffer(file_bytes, mime=True)
    if detected_mime not in PERMITTED_TYPES:
        return jsonify({"error": "file type not allowed"}), 400

    # Generate a new filename using UUID; derive the extension from the detected type, not from client input.
    file_extension = PERMITTED_TYPES[detected_mime]
    generated_name = f"{uuid.uuid4()}{file_extension}"
    destination = os.path.join(UPLOAD_DIR, generated_name)

    # Store the file under the generated name.
    with open(destination, "wb") as f:
        f.write(file_bytes)

    return jsonify({"status": "stored", "filename": safe_name}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix replaces the unsafe pattern with three defensive layers:

1. **Content Validation (Primary Defence):** Read the file bytes and detect the real MIME type using `python-magic.from_buffer()`, which inspects the file's magic bytes (prefix). Check the detected type against an allowlist (`PERMITTED_TYPES`). This prevents an attacker from uploading a PHP shell renamed as `.txt` or a DOCX file that is actually an executable.

2. **Generated Filename:** Replace the client-supplied filename with a UUID-based name (`uuid.uuid4()`). This removes the attacker's ability to choose what the server will store or serve back, preventing them from uploading `shell.php` and having that path remain executable.

3. **Deterministic Extension:** Derive the file extension from the allowlist-matched MIME type, not from the original filename. This ensures that a file detected as `application/pdf` is always stored with `.pdf` and served as such, regardless of what the attacker named it.

`secure_filename()` is retained only as a secondary sanitizer for the display name returned to the client (the `safe_name` in the JSON response), not as the validation step. The validation is now performed via magic-byte detection and allowlist matching, which is the true defence against CWE-434.

`python-magic` is a standard package that wraps libmagic and is required as a dependency for this fix.
