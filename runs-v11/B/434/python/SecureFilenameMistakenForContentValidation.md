## Verdict

Exploitable. The code uses `secure_filename()` to sanitize only the filename string, which prevents path traversal but does not validate the actual file content. An attacker can upload a dangerous file type (PHP script, executable, malicious document with active content) and it will be written to disk.

## Source

Line 14: `uploaded = request.files.get("document")` — attacker-controlled file upload

## Fix

**Vulnerable code (line 20–26):**

```python
    # secure_filename() strips path separators and unsafe characters from the
    # name, so this looked like enough sanitization to ship the endpoint.
    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    destination = os.path.join(UPLOAD_DIR, safe_name)
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    uploaded.save(destination)
```

**Fixed code:**

```python
import uuid
import magic

# At module level, define the allowlist of permitted types and the mapping from MIME type to extension.
ALLOWED_MIMETYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
MIMETYPE_TO_EXT = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
}

@app.route("/documents/upload", methods=["POST"])
def upload_document():
    """Accept a supporting document (PDF, DOCX, etc.) for the current case file."""
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    # secure_filename() sanitizes the filename string only; pair it with content validation.
    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    # Detect the actual file type from bytes and validate against allowlist.
    file_bytes = uploaded.read()
    detected_type = magic.from_buffer(file_bytes, mime=True)
    if detected_type not in ALLOWED_MIMETYPES:
        return jsonify({"error": "file type not allowed"}), 400

    # Generate a new filename derived from the detected type; do not use the client-supplied name for storage.
    file_extension = MIMETYPE_TO_EXT.get(detected_type, ".bin")
    storage_filename = str(uuid.uuid4()) + file_extension
    destination = os.path.join(UPLOAD_DIR, storage_filename)

    # Write the uploaded bytes to the storage location.
    with open(destination, "wb") as f:
        f.write(file_bytes)

    return jsonify({"status": "stored", "filename": safe_name}), 201
```

## Explanation

The fix adds mandatory file-content validation before storage. First, the uploaded file bytes are read and passed to `magic.from_buffer(file_bytes, mime=True)` to detect the true MIME type from the file's actual bytes, independent of the client-supplied filename extension or Content-Type header. The detected type is then checked against an allowlist (`ALLOWED_MIMETYPES`) of permitted types; if it does not match, the upload is rejected. After validation passes, the file is stored under a server-generated UUID-based filename whose extension is derived from the detected type via a fixed allowlist map (`MIMETYPE_TO_EXT`), ensuring the server controls what extension it will later serve the file as. The file is written through a file-handle context manager (`with open()`) rather than using werkzeug's `save()` method, giving explicit control over the bytes written. `secure_filename()` is retained as a secondary defense for display purposes only — it no longer gates the upload decision.

## Behaviour changes

1. **Added dependency**: The fix requires `python-magic` (`pip install python-magic` or `python-magic-bin` on Windows). This is a third-party library for detecting file types from bytes.

2. **Added configuration**: Module-level `ALLOWED_MIMETYPES` and `MIMETYPE_TO_EXT` dicts define the business logic for permitted types. This configuration must be maintained to reflect which file types the application actually needs to accept.

3. **Changed storage filename**: The uploaded file is now stored under a UUID-generated name (e.g. `a1b2c3d4-e5f6-7890-abcd-ef1234567890.pdf`) rather than a sanitized version of the client-supplied name. The original filename is still returned in the JSON response (`"filename": safe_name`) for display, but the actual stored file is unreachable by name guessing.

4. **File bytes read once and buffered**: `uploaded.read()` is called to load the entire file into memory for magic-byte detection and subsequent write. For very large uploads, this trades disk I/O for memory usage. If memory constraints are a concern, `magic` can operate on a partial buffer (`magic.from_buffer(uploaded.stream.read(8192), mime=True)` for the first 8KB), though this slightly reduces detection accuracy for some formats.

5. **Write mechanism changed**: The file is written using a standard file handle (`open(destination, "wb")`) instead of werkzeug's `UploadedFile.save()`. Both methods write the same bytes; the change makes the write explicit and allows for additional processing (e.g., re-encoding images) if needed in future hardening.

6. **Upload size is not bounded by this fix alone**: The fix does not impose a file-size limit. Pair it with Flask's `MAX_CONTENT_LENGTH` configuration to prevent disk exhaustion attacks.
