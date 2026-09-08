## Verdict

Confirmed. `secure_filename()` only neutralizes the *name* (strips path separators, `..`, drive letters, and unsafe characters) so the save target stays inside `UPLOAD_DIR`. It performs no check at all on what the file actually is. Nothing in the handler restricts the extension or inspects the content, so an attacker can upload a file with any extension and any payload (e.g. a `.php`, `.jsp`, `.html`, or `.svg` file, or a document whose declared extension does not match its real content) and have it stored under the upload directory. If that directory is ever served statically, reachable by an include/execute path, or consumed downstream by something that trusts the extension (a viewer, converter, or virus scanner bypass), this is a dangerous-type upload - CWE-434.

## Source

`request.files.get("document")` in `upload_document()` (`document_upload.py:14`) - a multipart file upload from an HTTP client, fully attacker-controlled: both `uploaded.filename` and the byte content of the file.

## Fix

### File: document_upload.py
```python
import os

import magic
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"

# Extensions this endpoint accepts. Keep in sync with ALLOWED_MIME_TYPES below -
# each entry here must have a corresponding sniffed MIME type there.
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"}

# MIME types as detected from the file's actual bytes (via libmagic), not as
# claimed by the filename extension or the client-supplied Content-Type header.
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
    "image/png",
    "image/jpeg",
}


def _extension(filename):
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() strips path separators and unsafe characters from the
    # name so the destination path stays inside UPLOAD_DIR, but it says
    # nothing about the file's actual type. That has to be enforced
    # separately: an extension allowlist plus a check of the real content.
    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    extension = _extension(safe_name)
    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "unsupported file type"}), 400

    # Sniff the real content instead of trusting the extension or the
    # client-supplied Content-Type: both are attacker-controlled and can
    # disagree with what the bytes actually are.
    header = uploaded.stream.read(2048)
    uploaded.stream.seek(0)
    detected_type = magic.from_buffer(header, mime=True)
    if detected_type not in ALLOWED_MIME_TYPES:
        return jsonify({"error": "file content does not match an allowed document type"}), 400

    destination = os.path.join(UPLOAD_DIR, safe_name)
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": safe_name}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The original code treated `secure_filename()` as if it were a content check. It is not: it is a *path-safety* transform - it removes `/`, `\`, `..`, and non-ASCII/unsafe characters so the resulting name can't escape `UPLOAD_DIR` or collide with a reserved name. It does nothing to the extension or the bytes that follow. A request can still name the file `payload.php` (sanitized to the same string, since it contains no unsafe characters) and upload arbitrary script content, or name a script `report.pdf` while the reserved extension check does not exist at all in the original code - either way the file lands on disk unchecked.

The fix adds two independent layers, both required:

1. **Extension allowlist** (`ALLOWED_EXTENSIONS`) - rejects obviously wrong file types (`.php`, `.jsp`, `.html`, `.svg`, `.exe`, etc.) before any content is even read. This is a fast reject, not the primary defense, because an extension is just a claim.
2. **Content-based type check** - `python-magic`'s `magic.from_buffer()` inspects the file's actual leading bytes (magic numbers: `%PDF-` for PDF, the ZIP local-file-header signature for DOCX, PNG/JPEG signatures, etc.) and returns the MIME type libmagic infers from content, independent of the filename or the `Content-Type` the client sent in the multipart body. Only a detected type in `ALLOWED_MIME_TYPES` is accepted. This is what actually closes CWE-434: even a file renamed to end in `.pdf` is rejected if its bytes are not a PDF.

`python-magic` wraps the system `libmagic` library, so the target environment needs `libmagic` available (via the OS package manager) alongside the `python-magic` PyPI package; check both are pinned to maintained versions during dependency review.

The stream is read from the start (`uploaded.stream.read(2048)` - enough for every signature above) and then rewound with `seek(0)` so `uploaded.save()` still writes the complete, untouched file content afterward.

Two things intentionally left unchanged, consistent with the finding's scope: the destination directory (`UPLOAD_DIR`) and the fact that the stored name keeps the client-supplied base name after sanitization. If `UPLOAD_DIR` is ever exposed by a web server, it should be configured to never execute scripts from that path (e.g. no PHP/CGI handler mapped there) as defense in depth, but that is a deployment/infrastructure control outside this file's diff, not a substitute for the type checks added here.
