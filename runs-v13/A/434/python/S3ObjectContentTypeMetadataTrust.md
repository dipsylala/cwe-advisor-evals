## Verdict

The upload function accepts and uses an untrusted `content_type` parameter directly in the S3 object metadata without validation. An attacker can set a dangerous content type (e.g., `application/x-executable`, `text/html`, `application/x-sh`) which could lead to code execution or injection attacks when the object is later accessed or served by a web server.

## Source

```python
def upload_avatar(bucket, key, file_bytes, content_type):
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

The vulnerability is at line 8: the `content_type` parameter flows directly to `s3.put_object()` without validation.

## Fix

```python
import boto3

s3 = boto3.client("s3")

# Whitelist of safe content types for avatar uploads
ALLOWED_CONTENT_TYPES = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
}


def upload_avatar(bucket, key, file_bytes, content_type):
    # Validate content type against whitelist
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise ValueError(
            f"Content type '{content_type}' is not allowed. "
            f"Allowed types: {', '.join(sorted(ALLOWED_CONTENT_TYPES))}"
        )
    
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

## Explanation

The fix adds a whitelist of safe MIME types for avatar uploads (`image/jpeg`, `image/png`, `image/gif`, `image/webp`) and validates the `content_type` parameter before passing it to S3. If the caller attempts to upload with a dangerous or unexpected content type, the function raises a `ValueError` immediately, preventing the malicious metadata from being stored.

This approach:
- Rejects executable, script, and other dangerous types at the point of upload
- Prevents downstream attacks when the object is served via HTTP or accessed by other systems
- Fails safely by raising an exception rather than silently accepting or stripping the value
- Uses an explicit whitelist rather than a denylist, which is more secure for the avatar-only use case
