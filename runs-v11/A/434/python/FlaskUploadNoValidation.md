## Verdict
CWE-434 is present. The code validates the MIME type header but does not validate the filename, enabling arbitrary file uploads with dangerous extensions or path traversal sequences.

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
```python
from flask import Flask, request
import os
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg"}
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    filename = file.filename

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        return {"status": "rejected"}, 400

    # Sanitize the filename to prevent path traversal
    filename = secure_filename(filename)
    
    if not filename:
        return {"status": "rejected"}, 400

    # Validate file extension against whitelist
    _, file_ext = os.path.splitext(filename)
    if file_ext.lower() not in ALLOWED_EXTENSIONS:
        return {"status": "rejected"}, 400

    # Generate a safe filename using UUID to prevent collisions and attacks
    safe_filename = f"{uuid.uuid4()}{file_ext}"
    destination = os.path.join(UPLOAD_DIR, safe_filename)
    
    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation
The vulnerability stems from two missing validations:

1. **Filename not validated**: `file.filename` is used directly without sanitization. An attacker can upload a file with a path traversal sequence like `../../../etc/passwd` or a dangerous extension like `shell.php.png` while spoofing the MIME type.

2. **MIME type is unreliable**: The header `content_type` is controlled by the client and can be forged. An attacker uploads an `.exe` with `content_type: image/png`.

The fix applies three defenses:

- **`secure_filename()`**: Werkzeug's utility removes path traversal sequences and null bytes from the filename. Rejects empty results.
- **Extension whitelist**: Validates the actual file extension against allowed types (`.png`, `.jpg`, `.jpeg`), case-insensitive. This catches double-extension attacks like `shell.php.png`.
- **UUID-based storage**: Replaces the user-supplied filename with a randomly generated one, preserving only the validated extension. This prevents collisions and neutralizes filename-based attacks entirely while maintaining the correct file type.

The MIME type check is retained as a first-pass filter but is not relied upon alone.
