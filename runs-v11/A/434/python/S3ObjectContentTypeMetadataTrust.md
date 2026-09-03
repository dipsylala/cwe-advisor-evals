## Verdict

The finding is valid. The function accepts an unconstrained `content_type` parameter and passes it directly to S3 metadata without validation, allowing an attacker to upload arbitrary file types by specifying any content type.

## Source

**Line 8** in `avatar_upload.py`:
```python
s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

The `content_type` parameter is received from the caller (line 6 function argument) and used without restriction.

## Fix

Validate the `content_type` against an allowlist of permitted types before uploading:

```python
import boto3

s3 = boto3.client("s3")

ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}

def upload_avatar(bucket, key, file_bytes, content_type):
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise ValueError(f"Content type '{content_type}' is not allowed. Allowed types: {ALLOWED_CONTENT_TYPES}")
    
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
```

Alternatively, infer the content type from file inspection rather than trusting the caller. Use a library like `python-magic` to detect the actual file type:

```python
import boto3
import magic

s3 = boto3.client("s3")

def upload_avatar(bucket, key, file_bytes):
    mime = magic.Magic(mime=True)
    detected_content_type = mime.from_buffer(file_bytes)
    
    allowed_types = {"image/jpeg", "image/png", "image/gif", "image/webp"}
    if detected_content_type not in allowed_types:
        raise ValueError(f"File type '{detected_content_type}' is not allowed")
    
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=detected_content_type)
```

## Explanation

CWE-434 occurs when uploaded file types are not restricted. Trusting the user-supplied `ContentType` parameter allows an attacker to upload executable files (`.exe`, `.php`, `.py`), scripts (`.js`), or other dangerous types by simply specifying a malicious content type, even if the file bytes do not actually match that type.

The remediation uses an allowlist to restrict uploads to safe image formats. The second approach is stronger because it validates the actual file content via magic bytes rather than trusting metadata, preventing polyglot attacks where the bytes do not match the declared type.
