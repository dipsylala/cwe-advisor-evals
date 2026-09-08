## Verdict

- **CWE-434** (Unrestricted Upload of File with Dangerous Type)
- **Location**: `FlaskUploadNoValidation.py`, line 18 (`file.save(destination)`)
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: `request.files["avatar"]` in `upload_avatar()` - both the uploaded bytes and `file.filename` are fully attacker-controlled multipart form data.
- **Gate (ineffective)**: line 15, `file.content_type in ALLOWED_CONTENT_TYPES`. `file.content_type` is read directly from the client-supplied `Content-Type` part header in the multipart body - an attacker sets this header to any value they like (e.g. `image/png`) regardless of what bytes follow, so the check is bypassed by simply lying in the request.
- **Sink**: line 16-18, `destination = os.path.join(UPLOAD_DIR, filename)` followed by `file.save(destination)`. The storage filename is the client-supplied `file.filename` verbatim - no sanitization, no re-derivation from real content - and `UPLOAD_DIR` (`static/uploads`) is inside Flask's static folder, so anything written there is directly served back by the app.
- **Sink contract**: `FileStorage.save()` writes the stream to `destination` and returns `None`; on failure (e.g. missing directory) it raises `OSError`, which the view does not catch. The current code discards nothing security-relevant and leaves size unbounded (no `MAX_CONTENT_LENGTH`).

Net effect: because the only type check is the spoofable `Content-Type` header, and the filename (and therefore extension) is taken from the client unmodified, an attacker can upload a file with arbitrary content and an arbitrary extension (e.g. a web shell named `x.php`) into a web-servable directory, defeating the app's intent to accept only PNG/JPEG avatars.

## Fix

### File: FlaskUploadNoValidation.py

```python
import os
import uuid

import magic
from flask import Flask, request

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_TYPES = {
    "image/png": "png",
    "image/jpeg": "jpg",
}

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    data = file.read()

    detected_type = magic.from_buffer(data, mime=True)
    extension = ALLOWED_TYPES.get(detected_type)

    if extension is None:
        return {"status": "rejected"}, 400

    filename = f"{uuid.uuid4().hex}.{extension}"
    destination = os.path.join(UPLOAD_DIR, filename)
    with open(destination, "wb") as out:
        out.write(data)

    return {"status": "ok", "path": destination}, 200


if __name__ == "__main__":
    app.run()
```

**Library recommendation**: `python-magic` (module name `magic`), used to detect the real MIME type from file bytes via `magic.from_buffer(data, mime=True)`. The loaded guidance names this library but carries no minimum-version floor, so no version is asserted here - confirm the resolved version through SCA/dependency-check tooling before merging. Note this package binds to the system `libmagic` library, which must be present on the host (or use the `python-magic-bin` wheel on platforms without it) - verify that operational dependency as part of the same review.

## Explanation

The fix replaces the spoofable `file.content_type` check with content-based type detection: the upload's actual bytes are read and passed to `magic.from_buffer(data, mime=True)`, and the result is checked against a fixed allowlist that maps each accepted MIME type to its canonical extension. Because the extension used for storage now comes from that allowlist match rather than from the client's filename, an attacker can no longer choose the stored file's effective type by naming it `x.php` or lying about `Content-Type`. The storage filename itself is replaced entirely with a server-generated `uuid4()` name, so client-supplied path segments and dangerous extensions never reach the filesystem path at all, closing the unrestricted-upload weakness at both the type-check and the filename layers identified in the guidance.

## Behaviour changes

- **Type check mechanism**: `file.content_type` (spoofable client header) replaced with `magic.from_buffer(data, mime=True)` (content-derived) - required to close the CWE-434 finding; this is the primary fix.
- **Storage filename**: original `file.filename` replaced with a generated `uuid4().hex` name; extension is taken from the `ALLOWED_TYPES` map keyed by detected MIME type rather than from the client's filename - required per guidance so the client can no longer choose the stored extension even when the content-type check passes.
- **Sink call**: `file.save(destination)` replaced with `file.read()` followed by `open(destination, "wb").write(data)`. This is a mechanical substitution, not a functional change to what gets written: the bytes must be read into memory before they can be passed to `magic.from_buffer()`, and reading the stream first would leave `FileStorage.save()` writing from an exhausted (EOF) stream, so the equivalent raw write replaces it. Same bytes, same destination, same failure mode (`OSError` on write failure, uncaught, matching the original).
- **Added size limit**: `app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024` is new - previously upload size was unbounded. This is an additive secondary control called for by the guidance ("Harden configuration"), not something the original code did. Requests whose body exceeds 5 MB will now be rejected by Flask (413) where they previously would have been accepted regardless of size; the 5 MB figure is an assumption and should be tuned to the application's actual avatar-size requirements.
- **Response shapes/status codes**: unchanged (`{"status": "ok", "path": ...}` / 200, `{"status": "rejected"}` / 400).

**Assumptions**:
- `python-magic` and its native `libmagic` dependency are available in the deployment environment; this was not verified against an installed package in this environment (see Library recommendation).
- The 5 MB `MAX_CONTENT_LENGTH` value is a placeholder pending confirmation of the real business requirement for avatar file size.
- `UPLOAD_DIR` (`static/uploads`) is left unchanged: avatars are expected to be publicly served, so keeping the destination inside the static folder is intentional here, on the basis that only content validated as PNG/JPEG can now reach it - not a webroot-escape omission.

**Verification**: The fixed file was copied to a scratch location outside the repository and checked with `python -m py_compile` (Python 3.13.12) - it compiled with no errors. `python-magic` was not installed in this environment, so the `magic.from_buffer(data, mime=True)` call was not executed at runtime; its signature and behavior are taken directly from the loaded language guidance rather than from recall.
