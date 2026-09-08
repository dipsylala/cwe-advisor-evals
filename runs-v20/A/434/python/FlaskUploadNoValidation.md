## Verdict

Confirmed. `upload_avatar` trusts the client-supplied `Content-Type` header as its only gate before writing the uploaded file to disk under the web-served `static/uploads` directory, and it writes using the client-supplied filename unmodified.

## Source

`file = request.files["avatar"]` at line 12 (the multipart upload, including its attacker-controlled `filename` and `content_type` attributes) in `FlaskUploadNoValidation.py`.

## Fix

`file.content_type` is a header the client sets and can set to anything (e.g. `image/png` while uploading a `.php` or `.phtml` script), so the `ALLOWED_CONTENT_TYPES` check at line 15 is not a real type check — it only filters honest clients. Combined with `filename` being used unmodified to build the save path, an attacker can upload a script with a spoofed `Content-Type` and a filename/extension of their choosing into a directory (`static/`) that Flask serves back over HTTP, turning the upload endpoint into a way to plant and then execute arbitrary server-side code (or, at minimum, attacker-controlled HTML/SVG for stored XSS).

The fix replaces the header-based check with:
- An extension allowlist enforced on the actual filename.
- Real content sniffing (via Pillow, decoding the image data itself) instead of trusting any client-declared type, rejecting anything that isn't a genuine, decodable image.
- A server-generated filename (random token + the extension implied by the *verified* image format) so the attacker never controls the on-disk filename or extension, closing both the dangerous-type upload and any path-traversal/overwrite angle from the original `filename`.

### File: FlaskUploadNoValidation.py
```python
import os
import uuid

from flask import Flask, request
from PIL import Image, UnidentifiedImageError

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"

# Map Pillow's detected format to the extension we will save with.
# Only genuinely-decoded images reach this map; the client's declared
# filename/content-type are never trusted for the extension.
ALLOWED_FORMATS = {
    "PNG": ".png",
    "JPEG": ".jpg",
}

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]

    # Bound how much we buffer/decode before we know it's a real image.
    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    if size == 0 or size > MAX_UPLOAD_BYTES:
        return {"status": "rejected"}, 400

    # Verify the upload is a genuine, decodable image by sniffing its
    # actual bytes rather than trusting the client-supplied Content-Type
    # header, which an attacker can set to anything regardless of the
    # file's real contents.
    try:
        with Image.open(file.stream) as img:
            img.verify()
            image_format = img.format
    except (UnidentifiedImageError, OSError):
        return {"status": "rejected"}, 400

    extension = ALLOWED_FORMATS.get(image_format)
    if extension is None:
        return {"status": "rejected"}, 400

    # Server-generated filename: the client's filename/extension is never
    # used to build the save path, which also removes any path-traversal
    # or overwrite risk from that value.
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    safe_filename = f"{uuid.uuid4().hex}{extension}"
    destination = os.path.join(UPLOAD_DIR, safe_filename)

    file.stream.seek(0)
    file.save(destination)
    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

- **Why the content-type check didn't help:** `file.content_type` comes straight from the multipart part's `Content-Type` header, which the uploading client sets in the request it constructs — it is not derived from the file's bytes in any way. A membership check against `ALLOWED_CONTENT_TYPES` therefore only rejects clients that don't bother to lie, which is not a security boundary.
- **Why the fix decodes the image instead of inspecting a magic-number prefix by hand:** `PIL.Image.open()` followed by `.verify()` parses the container/codec structure of the file, so a file that merely starts with a PNG/JPEG signature but is otherwise garbage (or polyglot with embedded script content) fails verification, whereas a byte-prefix check alone would not catch that. `Image.open` is called on the stream directly (no temp file with an attacker-chosen name is ever created).
- **Why the extension is derived from `img.format`, not the client's filename:** this removes the two remaining attacker-controlled inputs (filename and extension) entirely, so there is nothing left for a path-traversal or double-extension trick (`avatar.png.php`) to act on, and the file that lands in the web-served `static/uploads` directory is guaranteed by construction to be one of the two allowed image formats.
- **Size cap:** bounds decompression/memory use before Pillow processes an arbitrarily large upload; it is a defense-in-depth addition, not the primary fix for CWE-434.
- **Testing the fix:** confirm a genuine PNG/JPEG still uploads and returns `200` with a `.png`/`.jpg` path; confirm a text file renamed to `avatar.png` with `Content-Type: image/png` (the original bypass) is now rejected with `400`; confirm the saved file's name never echoes the client-supplied filename.
