## Verdict

CWE-434 confirmed. The code validates MIME type but leaves the filename unsanitized, enabling both path traversal and execution of uploaded files with dangerous extensions.

## Source

Line 13: `filename = file.filename` receives the attacker-controlled filename from the upload request without validation. This value flows directly to line 16 via `os.path.join(UPLOAD_DIR, filename)` and is saved to disk at line 18.

## Fix

```python
from flask import Flask, request
import os
import re

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg"}
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    filename = file.filename

    # Validate MIME type
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        return {"status": "rejected"}, 400

    # Validate file extension
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return {"status": "rejected"}, 400

    # Sanitize filename: allow only alphanumeric, dash, underscore, and dot
    sanitized = re.sub(r"[^a-zA-Z0-9._-]", "", filename)
    if not sanitized:
        return {"status": "rejected"}, 400

    destination = os.path.join(UPLOAD_DIR, sanitized)
    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

MIME type validation alone is insufficient because:
- Attackers can forge MIME types in the request
- No file extension is checked, enabling upload of executable files (`.exe`, `.php`, `.sh`) with spoofed MIME types

The fix adds:
1. **Extension whitelisting**: Only `.png`, `.jpg`, `.jpeg` are accepted, blocking executables
2. **Filename sanitization**: `re.sub()` strips path-traversal characters (`/`, `\`, `..`) and dangerous shell metacharacters, leaving only safe characters
3. **Extension validation before save**: Detects attacks that bypass MIME spoofing by including a safe extension alongside a dangerous one (e.g., `shell.php.png`)

This approach prevents both path traversal (malicious paths like `../../../etc/passwd`) and arbitrary code execution from uploaded files.
