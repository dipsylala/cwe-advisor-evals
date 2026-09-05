## Verdict

Exploitable

## Source

The `content_type` parameter passed to `upload_avatar()` from an untrusted caller (line 6). This value originates from client-supplied metadata (typically request headers or form data) and is never validated.

## Fix

**Vulnerable code:**

```python
import boto3

s3 = boto3.client("s3")


def upload_avatar(bucket, key, file_bytes, content_type):
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

**Fixed code:**

```python
import boto3
import magic
import uuid
from typing import Optional

s3 = boto3.client("s3")

# Allowlist of permitted MIME types for avatars
ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/webp', 'image/gif'}

# Map MIME type to file extension
MIME_TO_EXT = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/webp': '.webp',
    'image/gif': '.gif',
}


def upload_avatar(bucket, file_bytes):
    """Upload avatar after validating file type and content."""
    # Detect actual file type from magic bytes, not client-supplied metadata
    detected_mime = magic.from_buffer(file_bytes, mime=True)
    
    # Validate against allowlist of permitted types
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"File type {detected_mime} not allowed for avatars")
    
    # Generate server-controlled storage key with detected type
    extension = MIME_TO_EXT[detected_mime]
    key = f"avatars/{uuid.uuid4()}{extension}"
    
    # Use validated content type, not client-supplied parameter
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=detected_mime)
    
    return key
```

## Explanation

The fix eliminates the CWE-434 vulnerability by removing the trust boundary on client-supplied file metadata and implementing validation-based type detection. The original code accepted a `content_type` parameter from the caller without verification, allowing an attacker to upload a file with one content type while claiming it is another (e.g., uploading an HTML or SVG file with embedded script but claiming it is `image/jpeg`). The fixed code uses the `python-magic` library to detect the actual file type by inspecting the file's magic bytes (signature), compares the detected type against a server-maintained allowlist of permitted avatars (JPEG, PNG, WebP, GIF), and rejects anything outside that list. The storage filename is generated server-side using `uuid.uuid4()` rather than taken from client input, preventing attackers from exploiting S3's content-type handling to trigger unintended behavior. Only the validated MIME type is passed to `put_object()`, ensuring the S3 metadata reflects the actual content.

## Behaviour changes

1. **Function signature simplified** - Removed `key` and `content_type` parameters. Reason: these values must never come from the client; they must be server-generated (key) and server-determined (content-type from inspection).
2. **Return value added** - The function now returns the generated `key` instead of `None`. Reason: the caller must know the actual storage path so it can retrieve or reference the avatar later.
3. **Error handling** - Raises `ValueError` when the detected file type is not in the allowlist. Reason: early rejection prevents rejected files from reaching S3.
4. **New imports** - `magic`, `uuid`, and type hints. Reason: `magic.from_buffer()` performs content-based type detection, `uuid.uuid4()` generates server-controlled filenames.
5. **Configuration added** - `ALLOWED_MIME_TYPES` and `MIME_TO_EXT` constants. Reason: explicit allowlist enforcement and deterministic filename extension mapping prevent client-controlled extension injection.
