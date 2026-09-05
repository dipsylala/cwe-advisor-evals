## Verdict

**CONFIRMED** — The function trusts the client-supplied `content_type` parameter without validating the actual file content, allowing an attacker to upload executable or dangerous content while claiming a benign type. S3 stores the claimed type as-is in object metadata, and downstream code serving the file may trust that metadata to determine how to handle it.

## Source

The `content_type` parameter in the `upload_avatar()` function is attacker-controlled, passed from a request handler or upload endpoint without validation.

## Fix

```python
import boto3
import magic
import uuid

s3 = boto3.client("s3")

# Allowlist of permitted MIME types for avatars
ALLOWED_MIME_TYPES = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}


def upload_avatar(bucket, key, file_bytes, content_type):
    # Detect the actual MIME type from file content, not from client claim
    detected_mime = magic.from_buffer(file_bytes, mime=True)
    
    # Validate against allowlist
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Unsupported file type: {detected_mime}")
    
    # Generate a new storage key with extension derived from detected type
    extension = ALLOWED_MIME_TYPES[detected_mime]
    storage_key = f"{uuid.uuid4()}.{extension}"
    
    # Use the validated MIME type, not the client-supplied content_type
    s3.put_object(
        Bucket=bucket,
        Key=storage_key,
        Body=file_bytes,
        ContentType=detected_mime
    )
    
    return storage_key
```

## Explanation

The fix validates file content using `python-magic` to detect the actual MIME type from file bytes, independent of the client-supplied `content_type` header. This detected type is checked against an allowlist of permitted types (`image/jpeg`, `image/png`, `image/webp`). Only files matching the allowlist are accepted; rejecting unsupported types prevents upload of executable content (e.g., PHP, JavaScript, Windows executables) disguised as images.

The fix also generates a server-controlled storage key using `uuid.uuid4()` instead of trusting the client's supplied `key` parameter. The file extension is derived from the detected type through a fixed map, ensuring the stored file cannot be uploaded as `malicious.php` even if the attacker attempts to override the extension. S3 stores the validated MIME type in object metadata, not the client's claim.

The function now returns the generated storage key so the caller can associate the uploaded file with the correct path in S3.

## Behaviour changes

- **Different return value**: The function now returns the generated storage key instead of returning nothing, so callers must update to capture this value.
- **Different input validation**: The function now rejects uploads where the file content does not match one of the allowed MIME types (image/jpeg, image/png, image/webp), raising `ValueError` for unsupported types. Callers must handle this exception.
- **Different S3 key**: Files are no longer stored at the caller-supplied key. A new UUID-based key is generated instead, so retrieval logic must use the returned key or a database to map original uploads to stored paths.
- **New dependency**: The fix requires `python-magic` package for content-type detection. Confirm the version through dependency management before merging.
