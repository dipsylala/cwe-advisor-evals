## Verdict

exploitable (confidence: high)

CWE-434 (Unrestricted Upload of File with Dangerous Type) at `document_upload.py:26`. `secure_filename()` sanitizes the filename string only - it strips path separators and unsafe characters but performs no check of the file's actual type or content. No content-type or magic-byte validation exists anywhere on this path, so a client can upload any file whose sanitized name is accepted and have it written verbatim to disk under `UPLOAD_DIR`.

## Source

- Source: `uploaded = request.files.get("document")` (line 14) - the client-supplied multipart file part, including its bytes, filename, and `content_type`, all attacker-controlled.
- Data flow: `uploaded.filename` is passed through `secure_filename()` (line 20), producing `safe_name`, which is joined with `UPLOAD_DIR` into `destination` (line 24). `uploaded`'s bytes are never inspected.
- Sink: `uploaded.save(destination)` (line 26) - `werkzeug.datastructures.FileStorage.save()`, which writes the uploaded stream to `destination` verbatim. It returns `None`, raises `OSError` if the path is unwritable, and neither reads nor validates content type.
- Break: none. `secure_filename()` only removes path separators and unsafe characters from the name; it does not inspect the bytes, so a script or web shell with a sanitized name (e.g. `shell.php`, `shell.phtml`) reaches the sink unchanged. The finding is exploitable as reported.

## Fix

Library: `python-magic` (module `magic`), for content-based type detection via `magic.from_buffer(data, mime=True)`. The loaded guidance gives no minimum safe version for this package; confirm the resolved version against SCA/dependency-check tooling before merging, and note it requires the system `libmagic` library at deploy time.

### File: document_upload.py

```python
import os
import uuid

import magic
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"

# Fixed map from detected content type to the extension the server will store
# and later serve the file as - the client never gets to choose this half.
ALLOWED_MIME_TO_EXT = {
    "application/pdf": ".pdf",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
}


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() only sanitizes the name (strips path separators and
    # unsafe characters) - it says nothing about the file's actual content, so
    # it is kept here only to validate that a usable display name was supplied.
    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    # Detect the real type from the file's bytes and check it against an
    # allowlist, independent of the client-supplied filename and content-type.
    file_bytes = uploaded.read()
    uploaded.seek(0)
    detected_type = magic.from_buffer(file_bytes, mime=True)
    extension = ALLOWED_MIME_TO_EXT.get(detected_type)
    if extension is None:
        return jsonify({"error": "unsupported file type"}), 400

    # Store under a generated name whose extension comes from the detected
    # type, not the client-supplied filename, so the attacker never controls
    # what the file is later served or executed as.
    stored_name = f"{uuid.uuid4().hex}{extension}"
    destination = os.path.join(UPLOAD_DIR, stored_name)
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": stored_name}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix reads the uploaded stream's bytes and detects the real file type with `magic.from_buffer(data, mime=True)`, then checks that type against a fixed allowlist (`ALLOWED_MIME_TO_EXT`) that also supplies the extension the file will be stored under - closing both the missing-content-validation gap and the client-controlled-extension gap in one step, per the language guidance's "derive the stored extension from the detected type" principle. `secure_filename()` is kept but demoted to what it actually does: confirming a non-empty, safe display name; it no longer contributes to the storage path. The stream is read then `seek(0)` back to the start so `uploaded.save()` still writes the complete, unmodified file content, preserving the sink's existing "write the stream to `destination`" contract, its `None` return, and its `OSError`-on-failure behaviour. The stored filename is now a generated UUID with an allowlisted extension rather than a derivative of client input, so even an attacker who crafts an allowlisted-looking name can no longer influence what the file lands on disk as.

## Behaviour changes

- Requests whose real content does not match an allowlisted type (PDF, DOC, DOCX) now receive `400 {"error": "unsupported file type"}` instead of being stored - this is the intended effect of closing the finding, not incidental.
- The `filename` returned in the success response is now the generated storage name (e.g. `3f9c...b2.pdf`) instead of the sanitized original name - required because the fix stops using any client-derived value as the storage/reference path (guidance: "break taint after allowlist validation... use the generated filename for storage").
- The file's bytes are read into memory once via `uploaded.read()` for magic-byte detection, then the stream position is reset with `uploaded.seek(0)` before `uploaded.save()` - `FileStorage` wraps a seekable stream, so `save()` writes the same complete content as before; no other argument, return value, or error path of the sink changed.

Verification: `python -m py_compile` against the fixed file in a scratch copy - passed with no errors. `magic.from_buffer(data, mime=True)` and `uuid.uuid4()` are both named directly by the loaded language guidance and Python's standard library respectively; no other new names were introduced.

Assumption: the endpoint's business-required file types are inferred from the existing docstring ("PDF, DOCX, etc.") as PDF, DOC, and DOCX; the allowlist should be adjusted to the application's actual accepted set if it differs.
