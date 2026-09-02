## Verdict

Confirmed. The upload handler trusts client-supplied data for both the file's type and its name, so an attacker can place an arbitrary file - including an executable script - under the web-served `static/uploads` directory.

## Source

`request.files["avatar"]` at line 12, specifically its `.content_type` (line 15) and `.filename` (line 13) attributes. Both are values the client sets in the multipart upload request and are not verified server-side.

## Fix

```python
import os
import uuid
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

# Magic-byte signatures for the allowed image types, so the actual
# file content is verified instead of the client-supplied Content-Type.
FILE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg",
}


def detect_image_type(file_storage):
    header = file_storage.stream.read(8)
    file_storage.stream.seek(0)
    for signature, ext in FILE_SIGNATURES.items():
        if header.startswith(signature):
            return ext
    return None


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    original_name = secure_filename(file.filename or "")
    extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""

    detected_type = detect_image_type(file)

    if not original_name or extension not in ALLOWED_EXTENSIONS or detected_type != extension:
        return {"status": "rejected"}, 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    stored_filename = f"{uuid.uuid4().hex}.{extension}"
    destination = os.path.join(UPLOAD_DIR, stored_filename)
    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The original code makes two trust mistakes:

1. **`file.content_type` is attacker-controlled.** It is simply the `Content-Type` field the client wrote in the multipart form part; a browser or `curl` can send any file with `Content-Type: image/png` regardless of what the bytes actually are. Checking it accomplishes nothing - an attacker can upload a `.php`, `.html`, or `.svg` payload while declaring it an image, and the check at line 15 passes.
2. **`filename` from the client is used directly to build the save path.** `file.filename` carries the name the client chose, including its extension. Nothing in the handler strips path separators or forces a safe extension, so the value at line 16-18 can produce something like `../../app.py`, a filename containing `..` or leading slashes, or - since files land under `static/uploads`, which Flask serves directly - a file such as `shell.php` (or an HTML/SVG file containing script) that becomes web-accessible and, depending on the deployment stack, executable.

The fix addresses both:

- **Filename**: `werkzeug.utils.secure_filename()` strips directory components and unsafe characters, closing the path-traversal angle. The stored filename is then replaced entirely with a generated `uuid4` name plus a fixed, validated extension, so client-supplied names never reach the filesystem and cannot collide with or overwrite existing files.
- **Type**: instead of trusting the declared `content_type`, the fix reads the first few bytes of the uploaded stream and matches them against known magic-byte signatures for PNG and JPEG. Only a file whose real content matches an allowed image signature - and whose extension agrees - is accepted. This closes the gap where a script or HTML file is relabeled with an image `Content-Type` or a `.png`/`.jpg` extension.

Together, the extension allowlist, the content-signature check, and the server-generated filename ensure only genuine images are written, under names the server controls, so uploaded content cannot be used to plant an executable or actively-rendered file in a web-accessible directory. Verify by confirming a legitimate PNG/JPEG still uploads successfully, and that a script file renamed to `.png` (or a real PNG re-labeled with a disallowed `Content-Type`) is rejected because its magic bytes don't match.
