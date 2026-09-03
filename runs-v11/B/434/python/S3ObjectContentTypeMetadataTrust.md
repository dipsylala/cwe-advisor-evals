## Verdict

Exploitable

## Source

The `content_type` parameter passed to the `upload_avatar()` function (line 6), originating from an untrusted caller.

## Fix

**Vulnerable code:**
```python
def upload_avatar(bucket, key, file_bytes, content_type):
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

**Fixed code:**
```python
import boto3
import magic

s3 = boto3.client("s3")

# Allowlist of permitted MIME types
ALLOWED_CONTENT_TYPES = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
}

def upload_avatar(bucket, key, file_bytes, content_type):
    # Detect the actual file type from bytes using magic
    detected_type = magic.from_buffer(file_bytes, mime=True)
    
    # Validate detected type against allowlist
    if detected_type not in ALLOWED_CONTENT_TYPES:
        raise ValueError(f"File type '{detected_type}' is not permitted")
    
    # Use the server-validated, detected type for upload, not the client-supplied content_type
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=detected_type)
```

## Explanation

The vulnerability occurs because the function accepts `content_type` directly from the caller and passes it unchanged to S3's `put_object()` as ContentType metadata. An attacker can supply an arbitrary content type (e.g., claim `application/octet-stream` for a malicious script), and S3 will store that metadata. When the object is later served to a client, the server may trust S3's ContentType header and execute or serve the file accordingly, bypassing type validation.

The fix validates the actual file content using `python-magic` to detect the true MIME type from magic bytes, independently of any client-supplied claim. It then checks the detected type against an allowlist of permitted types. Only after validation passes does it upload to S3, using the server-determined type instead of the client-supplied value. This ensures S3's metadata reflects the actual file content, not an attacker's claim, preventing content-type-based bypasses.

## Behaviour changes

- **New dependency:** `python-magic` must be installed for magic-byte detection. The fix requires adding it to project dependencies.
- **Changed argument:** `ContentType` parameter now uses the validated `detected_type` instead of the client-supplied `content_type`, ensuring the stored metadata matches actual file content.
- **New validation logic:** The function now raises `ValueError` if the detected type is not in the allowlist, rejecting uploads of disallowed file types. Callers must handle this exception.
- **No changes to return value or S3 behavior:** `s3.put_object()` still returns the same response; the only observable change is that the stored ContentType reflects the actual file, and disallowed types are rejected before upload.
