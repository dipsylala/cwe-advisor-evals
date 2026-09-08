## Verdict

Confirmed. The code accepts a user-supplied `content_type` parameter and passes it directly to S3 without validating the actual file content. An attacker can upload a malicious file (e.g., a script) while claiming it is an image, causing it to be stored with the wrong content type and potentially served or executed based on that false claim.

## Source

The vulnerable function at line 6–8 trusts the caller-supplied `content_type` parameter:

```python
def upload_avatar(bucket, key, file_bytes, content_type):
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

The `content_type` parameter comes from untrusted user input (e.g., from a web request), and the code uses it directly without validating that the file's actual content matches the claimed type.

## Fix

### File: avatar_upload.py

```python
import boto3
import magic
import uuid

s3 = boto3.client("s3")

# Allowlist of permitted MIME types for avatars
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}

# Map MIME type to file extension for storage
MIME_TO_EXT = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp"
}


def upload_avatar(bucket, key, file_bytes, content_type):
    # Detect actual file type from bytes using magic bytes, not from client-supplied content_type
    detected_type = magic.from_buffer(file_bytes, mime=True)
    
    # Validate against allowlist of permitted types
    if detected_type not in ALLOWED_TYPES:
        raise ValueError(f"File type {detected_type} not allowed. Permitted types: {', '.join(sorted(ALLOWED_TYPES))}")
    
    # Generate a random storage filename with extension derived from detected type
    # This ensures that even if an attacker provides a misleading extension,
    # the stored filename's extension reflects the actual file type
    ext = MIME_TO_EXT[detected_type]
    safe_key = f"{uuid.uuid4()}.{ext}"
    
    # Use the detected and validated type, not the untrusted client-supplied content_type
    s3.put_object(Bucket=bucket, Key=safe_key, Body=file_bytes, ContentType=detected_type)
```

## Explanation

The fix addresses CWE-434 by implementing the three core defences:

1. **Detect actual file type from content**: Instead of trusting `content_type`, the code calls `magic.from_buffer(file_bytes, mime=True)` to inspect the file's actual magic bytes and determine its real MIME type. This detects when an attacker has uploaded a script while claiming it is an image.

2. **Validate against an allowlist**: The detected type is checked against `ALLOWED_TYPES`, rejecting any file type not required by the business logic. This prevents arbitrary file uploads.

3. **Generate a safe filename**: The storage key is regenerated as a UUID with an extension derived from the detected type via `MIME_TO_EXT`. This breaks the attacker's ability to control the stored filename or extension, ensuring that the server will later serve or handle the file based on the actual type, not the attacker's claim. If an attacker uploads `shell.php` (detected as text/x-php), it will be stored as `550e8400-e29b-41d4-a716-446655440000.png` only if the content is actually a PNG.

4. **Input validation before use**: The function raises a `ValueError` if the file type is not permitted, failing safely and preventing storage of dangerous types.

The `python-magic` library accurately identifies file types from their headers, and the allowlist ensures that only image types suitable for avatars are accepted.
