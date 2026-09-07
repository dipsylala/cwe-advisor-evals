## Verdict

CWE-434 confirmed. The code uses `secure_filename()` to sanitize the filename against path traversal, but performs no validation of the file's actual content or type. An attacker can upload malicious executables with benign extensions (e.g., a Python script with a `.pdf` extension) that may be executed or accessed by other parts of the application.

## Source

```python
uploaded.save(destination)
```

Line 26 writes the uploaded file to disk without verifying its content. The filename sanitization on line 20 protects only against path traversal and unsafe characters; it does not inspect the file's actual type or content.

## Fix

Add file-type validation by inspecting the file's content (magic bytes) using a library like `python-magic`, and reject files that do not match a whitelist of allowed types:

```python
import magic

ALLOWED_MIME_TYPES = {"application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}

@app.route("/documents/upload", methods=["POST"])
def upload_document():
    uploaded = request.files.get("document")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "no file provided"}), 400

    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400

    # Read the file content to detect its actual type
    file_content = uploaded.read()
    uploaded.seek(0)  # Reset for save operation
    
    mime_type = magic.from_buffer(file_content, mime=True)
    if mime_type not in ALLOWED_MIME_TYPES:
        return jsonify({"error": "file type not allowed"}), 400

    destination = os.path.join(UPLOAD_DIR, safe_name)
    uploaded.save(destination)

    return jsonify({"status": "stored", "filename": safe_name}), 201
```

Install `python-magic` via `pip install python-magic` (or `python-magic-bin` on Windows if the system libmagic is not available).

## Explanation

Filename sanitization alone does not prevent unrestricted file uploads. `secure_filename()` removes path separators and unsafe characters, defending against directory traversal, but an attacker can still upload a malicious file (executable, script, archive containing malware) disguised with a benign extension. Validating the file's actual MIME type by inspecting its content (magic bytes) ensures that only legitimate file types are accepted, preventing execution of disguised executables and reducing the attack surface. The whitelist of `ALLOWED_MIME_TYPES` restricts uploads to specifically authorized document formats; extension spoofing is ineffective because the content-based check cannot be bypassed by renaming the file.
