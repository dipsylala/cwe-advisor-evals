## Verdict
CONFIRMED - CWE-434 (Unrestricted Upload of File with Dangerous Type) at line 18.

## Source
```python
from flask import Flask, request
import os

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg"}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    filename = file.filename

    if file.content_type in ALLOWED_CONTENT_TYPES:
        destination = os.path.join(UPLOAD_DIR, filename)
        # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
        file.save(destination)
        return {"status": "ok", "path": destination}, 200

    return {"status": "rejected"}, 400


if __name__ == "__main__":
    app.run()
```

## Fix
### File: FlaskUploadNoValidation.py

```python
from flask import Flask, request
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    
    if not file or file.filename == "":
        return {"status": "rejected"}, 400
    
    # Sanitize filename to prevent path traversal attacks (e.g., ../../)
    safe_filename = secure_filename(file.filename)
    if not safe_filename:
        return {"status": "rejected"}, 400
    
    # Validate file extension against whitelist
    if "." not in safe_filename:
        return {"status": "rejected"}, 400
    
    file_ext = safe_filename.rsplit(".", 1)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        return {"status": "rejected"}, 400
    
    destination = os.path.join(UPLOAD_DIR, safe_filename)
    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation
The vulnerability stems from three weaknesses:

1. **Untrusted content-type header**: The HTTP `Content-Type` header is client-supplied and untrustworthy. An attacker can upload a PHP shell or executable and set `Content-Type: image/png` to bypass the check.

2. **Unsanitized filename**: Using `file.filename` directly creates a path traversal vulnerability. An attacker can upload with filename `../../etc/passwd.png` to write outside the intended directory.

3. **No file extension validation**: The code only checks the content-type, not the actual file extension. A file named `shell.php` might still be saved even if it claims to be an image.

The fix applies three defenses:

- **`secure_filename()`**: Werkzeug's built-in function removes directory traversal sequences (`.`, `..`, `/`) and other dangerous characters from the filename.
- **Whitelist extension validation**: Check the actual file extension against a hardcoded set of safe extensions (`png`, `jpg`, `jpeg`). This is language/runtime-agnostic unlike content-type.
- **Reject files without extension**: Prevents edge cases where an attacker uploads a file without an extension or with a manipulated name.

This prevents the upload of executables, scripts, or other dangerous file types while still allowing legitimate image uploads.
