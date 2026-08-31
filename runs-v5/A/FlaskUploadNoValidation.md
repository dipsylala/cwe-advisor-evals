## Verdict

Confirmed. The endpoint accepts an uploaded file and trusts client-supplied metadata to decide whether it is safe, then writes it to a web-served directory under an attacker-controlled name.

## Source

`file = request.files["avatar"]` (line 12) — the uploaded file object, including its attacker-controlled `filename` and `content_type` fields, both taken directly from the multipart request with no server-side verification.

## Fix

```python
import os
import uuid

from flask import Flask, request
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

ALLOWED_TYPES = {
    "image/png": {"extension": ".png", "format": "PNG"},
    "image/jpeg": {"extension": ".jpg", "format": "JPEG"},
}

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files.get("avatar")
    if file is None or not file.filename:
        return {"status": "rejected"}, 400

    # Reject on the declared type first (cheap check), but do not trust it -
    # it is just a client-supplied header at this point.
    declared = ALLOWED_TYPES.get(file.content_type)
    if declared is None:
        return {"status": "rejected"}, 400

    # Verify the bytes actually are the declared image type. Pillow decodes
    # the image header rather than trusting the Content-Type the client sent,
    # closing the gap where a renamed/relabeled executable or script is
    # uploaded with a spoofed image content type.
    try:
        with Image.open(file.stream) as image:
            image.verify()
            actual_format = image.format
    except (UnidentifiedImageError, OSError):
        return {"status": "rejected"}, 400
    finally:
        file.stream.seek(0)

    if actual_format != declared["format"]:
        return {"status": "rejected"}, 400

    # Discard the client-supplied filename entirely and generate a new one.
    # This removes path traversal, null-byte, and double-extension tricks
    # (e.g. "avatar.png.php") in one step, and fixes the extension to match
    # the verified content rather than whatever the client sent.
    safe_name = f"{uuid.uuid4().hex}{declared['extension']}"
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    destination = os.path.join(UPLOAD_DIR, safe_name)

    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The original handler makes its accept/reject decision using `file.content_type`, which is just the `Content-Type` field of the multipart part - a value the client sets and can set to anything, regardless of what bytes actually follow. An attacker uploads a web shell, HTML file, or SVG with embedded script and simply labels the part `image/png`; the check at line 15 passes and `file.save()` writes it, under the attacker's own `filename`, into `static/uploads`, which Flask serves directly to the web. Depending on the deployment (e.g. an `.htaccess`/handler mapping that executes scripts in that directory, or a browser that content-sniffs and renders an uploaded `.html`/`.svg` as active content instead of an image), this yields remote code execution or stored XSS from what looks like an image upload endpoint.

Two compounding issues make it worse than a single missing check:

1. **Filename is attacker-controlled and unsanitized.** `filename` from the client is joined into the destination path with no traversal check and no extension enforcement, so even a stricter content-type allowlist would not stop `..`-based traversal or a crafted name like `avatar.png.php` that some server configurations execute based on trailing extension.
2. **No verification of the actual file content.** Nothing reads the bytes to confirm they form a valid image before they are written to disk and served.

The fix addresses both: it decodes the upload with Pillow (`Image.open(...).verify()`) to confirm the bytes are a genuine image of the claimed format - this is a content check, not a header check, so a relabeled non-image file fails it - and it replaces the client-supplied filename with a server-generated name whose extension is derived from the verified format, eliminating traversal and extension-spoofing in the same step. A production deployment should also serve the uploads directory with script execution disabled and, for defense in depth, keep it outside the directly-served `static/` tree or front it with a CDN/object store that never executes uploaded content - but the two changes above close the direct CWE-434 finding at the validation point the scanner flagged.
