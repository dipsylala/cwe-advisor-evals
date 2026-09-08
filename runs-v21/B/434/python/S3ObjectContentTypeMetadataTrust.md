## Verdict

Exploitable. The function accepts `content_type` directly from the caller without validation and passes it to `s3.put_object()`. An attacker can upload a file with a malicious type while claiming it is an allowed type, and S3 will store it with the attacker's claimed MIME type.

## Source

The `content_type` parameter at line 8, which receives untrusted input from the caller (ultimately derived from client-supplied request headers or metadata). The flow is:

- Caller supplies `content_type` (attacker-controlled)
- Parameter passes directly to `s3.put_object(ContentType=content_type)` without validation

## Fix

### File: avatar_upload.py

```python
import boto3
import magic

s3 = boto3.client("s3")

# Allowlist of permitted MIME types for avatar uploads
PERMITTED_AVATAR_TYPES = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
}


def upload_avatar(bucket, key, file_bytes, content_type):
    # Detect the actual file type from the file bytes, not the client-supplied header
    detected_type = magic.from_buffer(file_bytes, mime=True)
    
    # Validate the detected type against the allowlist
    if detected_type not in PERMITTED_AVATAR_TYPES:
        raise ValueError(f"File type {detected_type} is not permitted for avatar uploads")
    
    # Use the detected type from file content, not the client-supplied content_type parameter
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=detected_type)
```

## Explanation

The fix replaces the trusted-client-supplied `content_type` with validation based on actual file content. The `magic.from_buffer()` function inspects the file's magic bytes (the leading bytes that identify file format) to detect the true MIME type, independent of any claim by the client. This detected type is then validated against a server-controlled allowlist of permitted types. Only files matching an allowlisted type proceed to S3, using their detected type rather than the client's claimed type. This prevents an attacker from uploading an executable script (e.g., PHP, JavaScript, or HTML) while claiming it is a JPEG, and forces the uploaded file's type to match its actual content.

## Behaviour changes

- **New dependency**: Requires `python-magic` library to be installed and available at runtime.
- **Validation enforcement**: The function now raises `ValueError` if the detected file type is not in `PERMITTED_AVATAR_TYPES`, rejecting any file that does not match an allowed type. The original code accepted all types without restriction.
- **MIME type source change**: The `ContentType` argument to `s3.put_object()` now comes from the detected file content (`detected_type`) instead of the caller's parameter. This is a breaking change only if the caller relied on the ability to upload files with mismatched types.
- **Slight performance impact**: Each upload now incurs the cost of magic byte detection, which is a small overhead on the file-read operation.
- **Taint break after allowlist**: The `content_type` parameter is no longer used; only the detected and validated type is passed downstream to S3. The parameter could be removed in a future refactor, but keeping it maintains API compatibility with existing callers.

