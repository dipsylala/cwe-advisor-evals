## Verdict

**Confirmed exploitable.** The code treats `secure_filename()` as sufficient file-type validation, but this function only sanitizes the filename string—it performs no content or type validation. An attacker can upload a malicious executable (e.g., a PHP webshell) with an allowed or spoofed extension, and the application will store and potentially execute it without validating the actual file content.

## Source

Line 14: `uploaded = request.files.get("document")` receives untrusted file data from the client.

The filename flows through:
- Line 20: `safe_name = secure_filename(uploaded.filename)` — sanitizes the filename but does not validate content
- Line 24: `destination = os.path.join(UPLOAD_DIR, safe_name)` — constructs path using the sanitized but unvalidated filename
- Line 26: `uploaded.save(destination)` — **SINK**: writes the file to disk without checking its actual type

## Fix

### File: document_upload.py

```python
import os
import uuid
import magic
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads/documents"

# Allowlist of permitted MIME types and their corresponding extensions
ALLOWED_MIME_TYPES = {
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

    # Read file bytes to validate actual content
    file_data = uploaded.read()
    if not file_data:
        return jsonify({"error": "empty file"}), 400
    
    # Detect real MIME type from file content (magic bytes)
    detected_mime = magic.from_buffer(file_data, mime=True)
    
    # Validate against allowlist of permitted types
    if detected_mime not in ALLOWED_MIME_TYPES:
        return jsonify({"error": "file type not allowed"}), 400
    
    # Generate new filename using UUID; derive extension from detected type
    file_extension = ALLOWED_MIME_TYPES[detected_mime]
    filename = f"{uuid.uuid4()}{file_extension}"
    destination = os.path.join(UPLOAD_DIR, filename)
    
    # Reset file pointer and save
    uploaded.seek(0)
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": filename}), 201


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix implements three layers of defense:

1. **Content-based type detection**: Instead of trusting the client-supplied filename or Content-Type header, the code now reads the file bytes and uses `magic.from_buffer(file_data, mime=True)` to detect the actual MIME type from the file's magic bytes. This prevents attackers from uploading a PHP webshell disguised with a `.pdf` extension.

2. **Allowlist validation**: The detected MIME type is checked against `ALLOWED_MIME_TYPES`, which explicitly lists only the business-required document types (PDF, DOCX, DOC, TXT). Any file that does not match one of these types is rejected immediately. This blocks executable files, scripts, archives, and other dangerous types regardless of how they are named.

3. **Generated filename with allowlist-derived extension**: Instead of using the client-supplied filename (even after `secure_filename()` sanitization), the code generates a new filename using `uuid.uuid4()` and appends the extension derived from the detected MIME type via the allowlist map. This ensures that the stored filename is under server control and cannot be manipulated by the attacker to influence how the file is later served or executed.

The original `secure_filename()` call has been removed because it is superseded by the content-based validation; file-type allowlisting and generated filenames provide defense-in-depth against both type-based and filename-based attacks.

**Dependencies**: This fix requires the `python-magic` library, which should be added to the project's dependency manifest. Ensure the version used is the current maintained release (verify against your SCA tooling).

## Behaviour changes

- **Rejection of disallowed types**: Files whose detected MIME type is not in `ALLOWED_MIME_TYPES` are now rejected with a 400 error. Previously, any file would be accepted.
- **Generated filenames**: Stored files no longer retain the client-supplied filename; they are stored under a UUID-based name with an extension derived from the detected type. The response now returns the generated `filename` instead of the `safe_name`.
- **Empty file handling**: Empty files are now explicitly rejected with a 400 error.
- **File pointer reset**: The file is read for type detection, then the file pointer is reset before saving. The `uploaded.save()` sink contract is preserved.

