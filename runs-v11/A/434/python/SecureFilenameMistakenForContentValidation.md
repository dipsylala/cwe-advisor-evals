## Verdict

**Confirmed.** The code accepts and stores files of any type without validating file extensions or content. `secure_filename()` sanitizes the filename string (removing path separators and unsafe characters) but does not restrict file types. An attacker can upload executable files (.php, .exe, .sh, etc.) that may be executed by the server or served to other users.

## Source

Line 26: `uploaded.save(destination)`

The vulnerability is the absence of file-type validation before saving. The code validates the filename format (line 20-22) but not the file extension or content type, assuming `secure_filename()` provides complete input validation when it does not.

## Fix

```python
import os
from pathlib import Path

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"
ALLOWED_EXTENSIONS = {"pdf", "docx", "doc", "txt", "xlsx", "xls"}


def is_allowed_file(filename):
    """Check if the file extension is in the whitelist."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # Check file extension against whitelist before any other processing
    if not is_allowed_file(uploaded.filename):
        return jsonify({"error": "file type not allowed"}), 400

    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    destination = os.path.join(UPLOAD_DIR, safe_name)
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": safe_name}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix adds a file-extension whitelist (`ALLOWED_EXTENSIONS`) and validates the uploaded filename against it before saving. The `is_allowed_file()` function:

1. Checks that the filename contains a dot (required for extension extraction)
2. Extracts the extension after the last dot
3. Converts it to lowercase for case-insensitive comparison
4. Returns `True` only if the extension is in the allowed set

This check is performed early (line 29-30), before `secure_filename()` is called, so dangerous file types are rejected immediately. The whitelist contains only document types safe to store and serve (PDF, Word, Excel, text files). The filename is still sanitized with `secure_filename()` afterward to remove unsafe characters from the name itself, but the extension validation ensures only known-safe types reach that point.

This is the primary defense for CWE-434: restrict uploads to a specific set of safe file types rather than attempting to block a list of dangerous ones (which is incomplete and brittle).
