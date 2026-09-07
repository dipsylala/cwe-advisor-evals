## Verdict

Exploitable. The function accepts a caller-supplied `content_type` parameter and passes it directly to `s3.put_object()` without validation. S3 stores this Content-Type metadata and serves it back in HTTP response headers. An attacker can upload a file containing HTML or JavaScript with a malicious Content-Type header (e.g., `text/html` or `application/javascript`), and when S3 serves the object, browsers will execute the script.

## Source

The `content_type` parameter at line 6 of `avatar_upload.py`. This parameter is attacker-controllable — it originates from the caller and is not validated before use.

## Fix

**Vulnerable Code:**
```python
def upload_avatar(bucket, key, file_bytes, content_type):
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

**Fixed Code:**
```python
import magic
from uuid import uuid4

# Allowlist of permitted MIME types for avatars
ALLOWED_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
}

# Map from MIME type to safe file extension
MIME_TO_EXT = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
}

def upload_avatar(bucket, file_bytes):
    # Detect the real content type from file bytes using magic number inspection
    detected_mime = magic.from_buffer(file_bytes, mime=True)
    
    # Validate against allowlist of permitted types
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Unsupported file type: {detected_mime}")
    
    # Generate a safe storage key with extension derived from detected type
    extension = MIME_TO_EXT[detected_mime]
    safe_key = f"{uuid4()}{extension}"
    
    # Upload using the detected and validated content type, not client-supplied metadata
    s3.put_object(Bucket=bucket, Key=safe_key, Body=file_bytes, ContentType=detected_mime)
```

## Explanation

The vulnerability exists because the original code trusts the client-supplied `content_type` parameter. S3 stores this as object metadata and serves it back in the Content-Type HTTP header, allowing an attacker to conduct content-type confusion attacks and cause browsers to execute embedded scripts.

The fix eliminates this by removing the untrusted `content_type` parameter and instead detecting the real file type by inspecting the actual bytes using `python-magic`. The detected type is then validated against an allowlist of business-required file types for avatars (JPEG, PNG, GIF, WebP). Only after passing the allowlist check is the detected type used for the S3 upload. This ensures that S3 serves the file with the correct Content-Type header based on the file's actual content, not an attacker's claim. The fix also generates a random storage key using `uuid4()` to prevent path traversal and prevent attackers from controlling how the file is stored or accessed.

## Behaviour changes

1. **Removed `key` parameter** — The original function accepted a caller-supplied storage key, which could enable path traversal or naming attacks. The fix generates a random key using `uuid4()` to prevent this.

2. **Removed `content_type` parameter** — The original function accepted and trusted this client-supplied value. It is now removed entirely since the content type is detected from the file bytes.

3. **Added `python-magic` dependency** — The fix requires the `python-magic` library to detect MIME types from file bytes. This is a required new dependency.

4. **Added validation with exception** — The original code performed no validation and would accept any file type. The fixed code raises a `ValueError` if the detected type is not in the allowlist. Callers must now handle this exception.

5. **Added ALLOWED_MIME_TYPES and MIME_TO_EXT constants** — These define the security policy for which file types are permitted and their safe extensions. They must be configured appropriately for the application's use case.

6. **Modified return behavior** — The original function implicitly returned the boto3 response. The fixed function's return value is now implicitly `None`. Callers must not rely on the put_object response.

7. **Extension handling** — The original code used the client-supplied filename (the `key` parameter), which could include any extension. The fixed code derives the extension from a server-controlled allowlist based on the detected MIME type, preventing attackers from controlling the file extension.
