## Verdict

CWE-434 confirmed. The endpoint accepts file uploads without validating the file type or extension, relying only on filename sanitization. An attacker can upload executable or otherwise dangerous files by providing an unsafe extension in the filename.

## Source

The vulnerability is in `document_upload.py` line 26. The code uses `secure_filename()` to sanitize the filename, which removes path separators and special characters but does not validate file type. The application then saves the uploaded file without confirming its extension is in an allowed list.

The attack: an attacker submits a file named `payload.exe`, `shell.php`, or `malicious.sh`. After `secure_filename()`, these names remain valid and are saved to disk, allowing execution of arbitrary code if the upload directory is web-accessible or processed by a script interpreter.

## Fix

### File: document_upload.py

```python
import os

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"
ALLOWED_EXTENSIONS = {"pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "txt"}


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() strips path separators and unsafe characters from the
    # name, but does not validate file type. Validate extension explicitly.
    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    # Validate file extension against allowlist
    _, ext = os.path.splitext(safe_name)
    ext = ext.lstrip(".").lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "file type not allowed"}), 400

    destination = os.path.join(UPLOAD_DIR, safe_name)
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": safe_name}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix adds explicit file type validation before saving:

1. **Allowlist definition**: `ALLOWED_EXTENSIONS` defines the only file extensions the application accepts. This is a product decision that enforces business requirements (documents only).

2. **Extension extraction**: `os.path.splitext()` extracts the extension reliably, even when the filename contains multiple dots.

3. **Normalization**: Convert to lowercase and strip leading dot to ensure case-insensitive and format-consistent matching.

4. **Allowlist validation**: Reject any file whose extension is not in the allowlist before saving. This blocks the attack vector entirely.

5. **Preservation of filename sanitization**: `secure_filename()` remains in the flow because it also prevents directory traversal and filesystem-level issues; the two defenses are complementary. Filename sanitization alone does not prevent file type attacks.

The fix closes the vulnerability by ensuring that only permitted document types can be stored, regardless of filename manipulation.
