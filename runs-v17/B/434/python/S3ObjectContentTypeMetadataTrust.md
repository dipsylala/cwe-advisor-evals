## Verdict

The vulnerability is real and exploitable. The function trusts the client-supplied `content_type` parameter without validating the actual file content, allowing an attacker to upload a file with a dangerous type (e.g., HTML or SVG with embedded JavaScript) by claiming a benign MIME type.

## Source

The `content_type` parameter passed to `upload_avatar()` originates from the caller (untrusted input). This value flows directly to `s3.put_object(..., ContentType=content_type)` at line 8 without any validation of the actual file content in `file_bytes`.

## Fix

Detect the actual file type from file content using `python-magic`, validate against an allowlist of permitted MIME types, and use the detected type instead of the client-supplied value. Generate a safe storage key based on the validated MIME type.

## Explanation

When `s3.put_object()` receives a client-controlled `ContentType`, an attacker can upload a file with arbitrary content (e.g., bytes containing JavaScript) while claiming it is an image via the `ContentType` header. If S3 serves the object directly or through CloudFront, the browser interprets the declared MIME type and may execute embedded active content. The fix detects the true file type from the file's magic bytes using `python-magic` and validates it against an allowlist, ensuring only permitted types proceed. The detected MIME type replaces the tainted `content_type` parameter in the `s3.put_object()` call, breaking the taint. Additionally, a server-generated filename using `uuid.uuid4()` with a validated extension replaces the client-supplied `key`, preventing directory traversal and ensuring files are stored outside user-controllable paths.

## Behaviour changes

- Function now requires the `python-magic` library to detect file types from content.
- Files are stored with auto-generated UUIDs and validated extensions instead of client-supplied keys.
- Only whitelisted image types (image/jpeg, image/png, image/gif, image/webp) are accepted; others raise `ValueError`.
- The S3 object `ContentType` header is now set to the detected MIME type, not the client's claim.
- The `key` parameter is accepted for backward compatibility but ignored; a safe key is generated internally.

### File: avatar_upload.py

```python
import boto3
import magic
import uuid

s3 = boto3.client("s3")

# Allowlist of permitted MIME types with file extensions
ALLOWED_MIME_TYPES = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
}


def upload_avatar(bucket, key, file_bytes, content_type):
    # Detect actual file type from content bytes
    detected_type = magic.from_buffer(file_bytes, mime=True)
    
    # Validate against allowlist
    if detected_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"File type not allowed: {detected_type}")
    
    # Generate a new safe filename from the detected type
    extension = ALLOWED_MIME_TYPES[detected_type]
    safe_key = f"{uuid.uuid4()}.{extension}"
    
    # Use the detected MIME type, not the client-supplied value
    s3.put_object(Bucket=bucket, Key=safe_key, Body=file_bytes, ContentType=detected_type)
```
