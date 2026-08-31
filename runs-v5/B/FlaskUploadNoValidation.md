## Verdict

CWE-434 (Unrestricted Upload of File with Dangerous Type) - **exploitable**. Confidence: high.

## Source

`request.files["avatar"]` in the `POST /profile/avatar` handler (Flask). Both the file bytes and `file.content_type` originate from the client-supplied multipart request and are fully attacker-controlled.

## Fix

Library: `python-magic` (content-type detection from bytes) and `Pillow` (image re-encode/verify). Both are already the libraries this knowledge base's Python CWE-434 guidance names. No minimum version is supplied here - confirm the resolved versions against SCA/dependency-check tooling before merging.

Vulnerable code:

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

Fixed code:

```python
from flask import Flask, request
import os
import uuid
from io import BytesIO

import magic
from PIL import Image

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_MIME_TO_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
}
PIL_FORMAT_FOR_EXT = {
    ".png": "PNG",
    ".jpg": "JPEG",
}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    data = file.read()

    detected_type = magic.from_buffer(data, mime=True)
    if detected_type not in ALLOWED_MIME_TO_EXT:
        return {"status": "rejected"}, 400
    ext = ALLOWED_MIME_TO_EXT[detected_type]

    try:
        Image.open(BytesIO(data)).verify()
        image = Image.open(BytesIO(data))  # reopen: verify() leaves the handle unusable
        clean_buffer = BytesIO()
        image.save(clean_buffer, format=PIL_FORMAT_FOR_EXT[ext])
    except Exception:
        return {"status": "rejected"}, 400

    filename = f"{uuid.uuid4().hex}{ext}"
    destination = os.path.join(UPLOAD_DIR, filename)
    with open(destination, "wb") as out:
        out.write(clean_buffer.getvalue())

    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The original handler gated the upload on `file.content_type`, a client-supplied multipart header that a caller can set to `image/png` while uploading any file (e.g. a script or web shell), and it then saved that file under its original filename into `static/uploads` - a directory Flask serves directly, so an accepted dangerous type would be both stored and reachable. The fix drops the header check and instead reads the file bytes and detects the real type with `python-magic`, checked against a fixed MIME-to-extension allowlist map, so the extension used for storage is the one the allowlist assigns to the detected type rather than anything derived from client input. Because a magic-byte match only confirms a valid prefix and does not rule out a polyglot (a genuine PNG/JPEG header followed by embedded active content), the file is also opened and verified with Pillow and then re-encoded to a fresh buffer in the format that matches the allowlisted extension; only that re-encoded output is written to disk, under a newly generated `uuid4` filename. This closes the weakness because the stored file's bytes and extension are now both derived from server-side verification of actual content, not from anything the client asserted, and any file that fails to parse or verify as a real image of the expected type is rejected rather than saved.

## Behaviour changes

- The client-supplied `filename` is no longer used anywhere (not even sanitized) - the stored name is a generated `uuid4().hex` plus an allowlist-derived extension. Reason: using the original name (or any derivative of it) lets the client influence the storage path/extension, which the guidance requires breaking.
- The saved file's bytes are the Pillow re-encoded output, not the client's original bytes. Reason: re-encoding is the step that strips any active-content payload a polyglot file could carry past the magic-byte check; a straight byte-for-byte save would not close that gap.
- A file that has an allowed magic-detected MIME type but fails `Image.verify()`/re-encode (corrupt or non-image data disguised with a valid signature) now also returns `{"status": "rejected"}, 400`. Reason: this extends the existing "wrong type" rejection path to cover a case the original content-type check could never catch; the response shape and status code are unchanged from the existing rejection branch.
- `file.content_type` is no longer read or checked. Reason: it is an attacker-controlled request header and was the vulnerable check being replaced; the real-type detection from bytes now performs the allowlist decision it was standing in for.
- Files continue to be written under `UPLOAD_DIR` (`static/uploads`), which remains inside Flask's statically-served tree. This was not changed: because the stored extension is now constrained to `.png`/`.jpg` from server-verified, re-encoded image content, the file cannot carry executable script, satisfying the guidance's "storage incapable of executing scripts" alternative without altering how avatars are served back to clients. Moving storage fully outside the webroot remains a defense-in-depth option not applied here to keep the change scoped to the reported finding.
- `MAX_CONTENT_LENGTH` is not set. This is a recommended secondary hardening step from the guidance (bounding upload size) but is not part of closing the dangerous-type-upload weakness itself, so it is left as a follow-up rather than folded into this fix.

## Assumptions

- Language inferred as Python/Flask from the file's imports (`flask`) and route decorator syntax; not ambiguous.
- `UPLOAD_DIR` is assumed to be relative to the Flask app's working directory such that `static/uploads` resolves under the app's `static` folder (matching Flask's default static-serving convention) - this is why webroot exposure was treated as real rather than assumed away.
