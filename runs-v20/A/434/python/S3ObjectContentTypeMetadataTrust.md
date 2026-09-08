## Verdict

Confirmed. `upload_avatar` writes the caller-supplied `content_type` argument directly into the S3 object's `ContentType` metadata with no validation. `ContentType` is not just cosmetic metadata: when the object is later retrieved (via a presigned URL, an S3 static-website endpoint, or a CDN in front of the bucket), browsers and CDNs use it to decide how to render the response. An attacker who controls this value on an "avatar" upload can set it to `text/html` (or `image/svg+xml`, which browsers execute as HTML/SVG script), causing the stored file to be rendered/executed as active content rather than displayed as an inert image — turning an avatar-upload feature into a stored-XSS / dangerous-file-serving primitive. This is exactly the CWE-434 pattern: the "type" of the uploaded file that matters for safety is trusted from attacker-supplied metadata instead of being independently determined and restricted.

## Source

- Untrusted input: the `content_type` parameter of `upload_avatar(bucket, key, file_bytes, content_type)`. In a real avatar-upload endpoint this is populated from client-controlled data — the `Content-Type` header of the multipart part, or a form field — and is never verified against the actual bytes of `file_bytes`.
- Sink: `s3.put_object(..., ContentType=content_type)` at line 8, which stores the attacker-chosen value as the object's `Content-Type` and is honored verbatim by S3/CloudFront/browsers on retrieval.
- No sanitization, allowlist check, or independent type detection occurs between source and sink.

## Fix

### File: avatar_upload.py
```python
import boto3

s3 = boto3.client("s3")


def _sniff_image_content_type(file_bytes):
    """Determine the image MIME type from the file's own magic bytes.

    Returns the safe content type for a recognized image format, or None
    if file_bytes does not match one of the allowed formats. This ignores
    any caller-supplied content type claim entirely.
    """
    if file_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if file_bytes.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":
        return "image/webp"
    return None


def upload_avatar(bucket, key, file_bytes, content_type):
    # The content_type argument is attacker-controlled metadata (e.g. a
    # request header) and is never trusted or forwarded to S3. Instead the
    # content type stored with the object is derived from the file's own
    # magic bytes and restricted to a fixed allowlist of image formats. A
    # non-image payload (HTML, SVG-as-script, an executable, etc.) is
    # rejected outright, so the stored object can never be served with a
    # dangerous or attacker-chosen Content-Type.
    safe_content_type = _sniff_image_content_type(file_bytes)
    if safe_content_type is None:
        raise ValueError("Unsupported or unrecognized image file type")

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=file_bytes,
        ContentType=safe_content_type,
    )
```

## Explanation

The vulnerable code let the uploader dictate how their own file would later be interpreted by treating `content_type` as trustworthy metadata rather than as untrusted input traveling alongside untrusted bytes. Because S3 (and anything serving objects out of it, including CloudFront and S3 static website hosting) returns the stored `Content-Type` header on `GET`, an attacker could upload an HTML or SVG payload as their "avatar" while claiming `image/png` was untrustworthy in the wrong direction — they instead claim a *renderable* type like `text/html`, so the object comes back and executes in the victim's browser when the avatar URL is visited or embedded, achieving stored XSS.

The fix removes trust in the caller-supplied value entirely: it never reaches `put_object`. Instead, the actual bytes are sniffed against the magic-number signatures of a small, explicit allowlist of image formats (JPEG, PNG, GIF, WEBP) and the `ContentType` written to S3 is always one the server itself determined from real file content. Anything that does not match a known image signature — including HTML, SVG, JavaScript, or any other executable/dangerous type — is rejected before the upload proceeds, so it's impossible for the stored object to end up served with a `Content-Type` that causes a browser to render or execute it as anything other than a static image. Detecting type from content instead of from a client-asserted label is the standard remediation for CWE-434, and using a small positive allowlist (rather than trying to blocklist dangerous types) avoids missing an unanticipated dangerous format.
