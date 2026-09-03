## Verdict

Confirmed. The code at line 26 saves an uploaded file without validating its actual type or content. `secure_filename()` only sanitizes the filename string (strips path separators and unsafe characters); it performs no validation of the file's bytes. An attacker can upload an executable script, a web shell, or polyglot file with a safe-looking extension and have it written to disk where it may later be executed or served back to users.

## Source

Line 14: `uploaded = request.files.get("document")` - the uploaded file object from the HTTP request.

## Fix

```python
import os
import uuid
import magic

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"

# Map allowed MIME types to file extensions
ALLOWED_TYPES = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/msword": ".doc",
}


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() sanitizes the filename string only; it does not validate content.
    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    # Read file bytes and detect the real type using magic bytes, not filename or header.
    file_bytes = uploaded.read()
    detected_type = magic.from_buffer(file_bytes, mime=True)

    # Check that the detected type is in the allowlist.
    if detected_type not in ALLOWED_TYPES:
        return jsonify({"error": "file type not allowed"}), 400

    # Generate a new filename using the detected type's extension, not the original.
    extension = ALLOWED_TYPES[detected_type]
    generated_name = str(uuid.uuid4()) + extension
    destination = os.path.join(UPLOAD_DIR, generated_name)

    # Save the file under the generated name.
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": safe_name}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix adds content-based validation using `python-magic` to detect the actual file type from the file's bytes (magic header), independent of the client-supplied filename or Content-Type header. Before saving, the detected MIME type is checked against an allowlist of permitted types (`application/pdf`, `application/msword`, etc.). Only if the type is allowlisted does the code proceed.

The filename used for storage is generated (via `uuid.uuid4()`) rather than derived from the client-supplied name. The extension is determined by the allowlist map based on the detected type, so the extension cannot be manipulated by the attacker to cause misclassification when the file is later served. `secure_filename()` is retained for sanitizing the original filename in the response, maintaining defence-in-depth.

This eliminates the ability to upload executable content or polyglots by disguising them with a safe extension, because the validation is based on the file's actual bytes, not its name.

## Behaviour changes

- **New dependency**: `python-magic` must be installed and imported; add `python-magic` to `requirements.txt`.
- **New return value on error**: Returns 400 with `{"error": "file type not allowed"}` if the detected MIME type is not in `ALLOWED_TYPES`.
- **Storage filename changes**: Uploaded files are now stored under randomly generated names (e.g., `550e8400-e29b-41d4-a716-446655440000.pdf`) rather than sanitized versions of the original filename.
- **Response filename preserved**: The `filename` field in the 201 response continues to return the original sanitized filename, so the client sees what they uploaded even though the server stores it under a different name.
- **Extension derivation**: File extensions on disk are now determined by the allowlist map, not the uploaded file's original extension.
