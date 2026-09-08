## Verdict

exploitable (confidence: high)

CWE-434, Unrestricted Upload of File with Dangerous Type. `upload_avatar()` writes attacker-controlled bytes to S3 and stamps the object with an attacker-controlled `Content-Type`, with no check that the bytes are actually the image type the endpoint claims to handle. Nothing between the function's parameters and the `put_object` call constrains either value, so the path is live.

## Source

- Source: the `file_bytes` and `content_type` parameters of `upload_avatar()` - in an avatar-upload endpoint these come directly from the client's multipart request body and its `Content-Type` part header, which the client fully controls.
- Sink: `s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)` at line 8 of `avatar_upload.py`, which persists the raw bytes and stamps the object's metadata with the unvalidated `content_type` verbatim.
- Data flow: both tainted parameters reach the sink with no validation, allowlist check, or content inspection in between - the file forming the whole call chain is this one function.
- Assumption: `bucket` and `key` are treated as server-controlled (e.g. built from an authenticated user id) and out of scope for this fix; only `file_bytes` and `content_type` are attacker-controlled per the case's own naming (content-type metadata trust). If `key`'s extension is also client-influenced, the general CWE-434 guidance additionally recommends deriving the stored extension from the detected type rather than the caller-supplied name - flagged here as an assumption, not implemented, since it is not evidenced by this single-function call chain.

## Fix

Library recommendation: `python-magic` (module `magic`) for byte-level MIME detection, and `Pillow` (module `PIL.Image`) to verify and re-encode the image, both named by the loaded CWE-434 Python guidance. The guidance carries no minimum safe version for either package for this use - confirm the resolved version against SCA/dependency-check tooling before merging.

### File: avatar_upload.py

```python
import io

import boto3
import magic
from PIL import Image

s3 = boto3.client("s3")

# Allowlist of avatar image types this endpoint accepts. The client-supplied
# content_type is never trusted for this decision.
ALLOWED_AVATAR_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}


def upload_avatar(bucket, key, file_bytes, content_type):
    # Detect the real type from the file's bytes; content_type is just a
    # client-controlled request header and is not used for the storage
    # decision below.
    detected_type = magic.from_buffer(file_bytes, mime=True)
    if detected_type not in ALLOWED_AVATAR_TYPES:
        raise ValueError(f"Unsupported avatar file type: {detected_type}")

    # Confirm the bytes actually decode as the claimed image format, then
    # re-encode through Pillow so any active content smuggled past the
    # signature check (a polyglot) does not survive into storage.
    try:
        with Image.open(io.BytesIO(file_bytes)) as img:
            img.verify()
        with Image.open(io.BytesIO(file_bytes)) as img:
            output = io.BytesIO()
            img.save(output, format=img.format)
            safe_bytes = output.getvalue()
    except Exception as exc:
        raise ValueError("Uploaded avatar failed image validation") from exc

    # Use the detected, allowlisted type for the object's stored metadata,
    # not the client's claimed content_type.
    s3.put_object(Bucket=bucket, Key=key, Body=safe_bytes, ContentType=detected_type)
```

## Explanation

The fix stops trusting either client-supplied signal about the file's type. `magic.from_buffer()` inspects the actual bytes and is checked against a fixed allowlist of avatar-appropriate image MIME types, closing off the dangerous-type upload (e.g. an HTML/SVG document carrying script, or any non-image payload) regardless of what `content_type` claimed. Because a signature check alone only confirms a valid header prefix and a polyglot can carry a valid image header followed by active content, the bytes are also round-tripped through `Image.open()` / `img.verify()` and then re-opened and re-saved (`img.save(output, format=img.format)`) before upload - the re-encode step is what strips any payload appended past the point Pillow actually parses. The object is finally written to S3 with `ContentType` set to the detected, allowlisted MIME type rather than the caller's claim, so the stored metadata can no longer be used to make S3 (or anything serving from it) treat the object as a dangerous type. `bucket` and `key` are left untouched, consistent with the assumption that they are server-controlled.

Verification: `python -m py_compile` on the fixed file succeeded (syntax only - `magic`/`PIL` are not installed in this environment, so import resolution was checked by name against the loaded guidance instead, which names both `python-magic`'s `magic.from_buffer(data, mime=True)` and Pillow's `Image.open()` / `img.verify()` / re-encode pattern verbatim). Every other symbol used (`io.BytesIO`, `ValueError`) is Python standard library / builtin.

## Behaviour changes

- `Body` written to S3 is now the Pillow-re-encoded bytes, not the original `file_bytes` - required to strip any active content a polyglot could carry past the signature check; the re-encoded image is visually equivalent but not byte-identical to the input.
- `ContentType` written to S3 is now the detected MIME type, not the caller's `content_type` argument - this is the fix itself, not incidental.
- The function now raises `ValueError` for a file whose real type is not in the avatar allowlist, or whose bytes fail to parse as that image format - the original function had no rejection path and would upload anything. Callers must handle this new exception.
- The `content_type` parameter is now unused (kept for interface compatibility with existing callers) rather than being read into the request. No other parameter, argument, or return value changed; `bucket` and `key` are passed through unmodified.
