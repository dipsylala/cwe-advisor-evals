## Verdict

- **CWE-434** (Unrestricted Upload of File with Dangerous Type)
- **Location**: `FlaskUploadNoValidation.py`, line 18 (`file.save(destination)`)
- **Verdict**: exploitable
- **Confidence**: high - the flow from request to disk write is direct, with no content validation on the path that reaches the sink
- **Assumption**: `python-magic` (with its `libmagic` system dependency) and `Pillow` are treated as acceptable new dependencies for the fix, matching the CWE-434 Python guidance's recommended detection/re-encode mechanism. No minimum version is asserted for either - confirm the resolved versions against SCA/dependency-check tooling before merging, since none is supplied here from recall.

## Source

- **Source**: `request.files["avatar"]` - an attacker-controlled multipart file upload, specifically its `filename` and byte content.
- **Sink**: `file.save(destination)` at line 18, which writes the uploaded bytes verbatim to `UPLOAD_DIR` (`static/uploads`), inside Flask's default static-serving path.
- **Data flow**: `filename = file.filename` (line 13, unsanitized, never passed through `secure_filename()`) is joined directly into the storage path at line 16 (`os.path.join(UPLOAD_DIR, filename)`), then written unmodified by `file.save()` at line 18. The only gate before the sink is `file.content_type in ALLOWED_CONTENT_TYPES` (line 15), and `content_type` is a client-supplied multipart header, not a property of the actual bytes - trivially spoofed to any allowlisted value regardless of what the file actually contains. Nothing on this path inspects file content, so a script or HTML/SVG payload with a forged `Content-Type: image/png` header reaches disk under an attacker-chosen filename in a directory Flask serves back to the public. No check breaks this path before the sink, so the finding is confirmed exploitable, not merely unproven.

## Fix

**Library recommendation**: `python-magic` for content-sniffing (`magic.from_buffer(data, mime=True)`) and `Pillow` for image verification/re-encoding, per the loaded CWE-434 Python guidance. The guidance supplies no minimum safe version for either; confirm current versions via SCA tooling rather than pinning from this proposal. Add to the manifest (e.g. `requirements.txt`): `python-magic` and `Pillow`.

Vulnerable code (lines 10-21):

```python
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
```

Fixed code:

```python
from flask import Flask, request
import os
import io
import uuid
import magic
from PIL import Image

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_MIME_TO_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    data = file.read()

    detected_type = magic.from_buffer(data, mime=True)
    if detected_type not in ALLOWED_MIME_TO_EXT:
        return {"status": "rejected"}, 400

    try:
        Image.open(io.BytesIO(data)).verify()
        image = Image.open(io.BytesIO(data))  # reopen: verify() leaves the handle unusable
    except Exception:
        return {"status": "rejected"}, 400

    ext = ALLOWED_MIME_TO_EXT[detected_type]
    stored_filename = f"{uuid.uuid4().hex}{ext}"
    destination = os.path.join(UPLOAD_DIR, stored_filename)
    image.save(destination)
    return {"status": "ok", "path": destination}, 200
```

## Explanation

The fix replaces the spoofable `file.content_type` header check with a content-based allowlist: `magic.from_buffer()` inspects the actual uploaded bytes and returns a MIME type used both as the allowlist key and, via `ALLOWED_MIME_TO_EXT`, as the source of the stored extension - the same canonical value drives both decisions, so a forged header can no longer smuggle a mismatched extension through. `Image.open(...).verify()` confirms the bytes genuinely parse as the claimed image format (rejecting a polyglot whose header matches but whose body doesn't decode), and re-opening and re-saving through Pillow re-encodes the pixel data, which strips any active content (script, embedded HTML) a raw byte-for-byte copy would have preserved. The client-supplied `filename` is dropped entirely from the storage path; the stored name is a `uuid4()`-generated value with an extension taken only from the detected-type map, so neither the attacker's original name nor its extension ever reaches `os.path.join()` or the filesystem - closing both the dangerous-type upload and the incidental path-traversal exposure from joining an unsanitized filename into a directory path.

## Behaviour changes

- **Storage filename changed from client-supplied to generated**: `destination` is now built from a `uuid4()` name plus a mapped extension instead of the original `filename`. Required by the guidance's taint-break step (never let the client choose the stored extension); the returned `path` in the JSON response reflects the new name, which is a visible response-shape change for any caller that expected the original filename back.
- **Uploaded bytes are re-encoded, not stored verbatim**: `image.save(destination)` writes Pillow's re-encoded output rather than a raw copy of the upload. This can alter file size, recompress JPEG data, or drop EXIF/metadata the original file carried - an intentional trade-off, since re-encoding is what strips a polyglot's embedded active content; a byte-identical copy would not close that gap.
- **Validation source changed from header to content**: the accept/reject decision now depends on `magic.from_buffer()` and Pillow's parser instead of the client's `Content-Type` header. A request that previously passed by sending an allowlisted header on non-image bytes will now be rejected (closing the vulnerability); a request whose real bytes are a valid PNG/JPEG but sent an incorrect header will now be accepted where it was previously rejected - both are the intended effect of validating content instead of a client claim.
- **Storage location unchanged (`static/uploads`)**: the guidance's general preference is to store outside the webroot; this fix keeps the existing directory rather than relocating it, since files reaching that directory are now guaranteed to be re-encoded images from an allowlisted MIME set rather than arbitrary attacker content, and relocating would additionally break the app's existing static-serving of avatars, a behaviour outside this finding's scope. Moving storage outside the webroot and serving avatars through an application-controlled route remains a reasonable additional hardening step to consider separately.
- **No change to size limits**: `MAX_CONTENT_LENGTH` is not set by this fix. The guidance lists it as a secondary/defence-in-depth control, not the mechanism that closes CWE-434 itself; adding it is recommended as a follow-up but was left out here to keep this change scoped to the reported finding.
