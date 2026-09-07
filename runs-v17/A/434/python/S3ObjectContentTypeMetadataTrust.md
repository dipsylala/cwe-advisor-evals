## Verdict

Confirmed. The code trusts the `content_type` parameter directly from user input without validation, allowing an attacker to upload any file type with a spoofed MIME type and bypass content-type restrictions.

## Source

Line 8 in `avatar_upload.py`:

```python
s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

The vulnerability is that `content_type` is user-controlled and passed directly to S3 without validating it against a whitelist of allowed types.

## Fix

### File: avatar_upload.py

```python
import boto3

s3 = boto3.client("s3")

ALLOWED_AVATAR_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}


def upload_avatar(bucket, key, file_bytes, content_type):
    # Validate content type against whitelist of safe types
    if content_type not in ALLOWED_AVATAR_TYPES:
        raise ValueError(f"Invalid content type: {content_type}. Allowed types: {ALLOWED_AVATAR_TYPES}")
    
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

## Explanation

CWE-434 arises when an application accepts file uploads without restricting the file type. An attacker can upload a malicious executable (e.g., .exe, .sh, .jar, .php) with a spoofed content type (e.g., claiming `image/jpeg`), which may later be executed or served to users if access controls are insufficient.

The fix implements a whitelist of allowed MIME types for avatar uploads (`image/jpeg`, `image/png`, `image/gif`, `image/webp`). Before uploading to S3, the function validates that the provided content type is in the whitelist. If not, it raises a `ValueError` that the caller should catch and handle with an appropriate HTTP error response (e.g., 400 Bad Request). This ensures that only image files approved for avatars can be stored, preventing an attacker from uploading dangerous file types disguised as images.
