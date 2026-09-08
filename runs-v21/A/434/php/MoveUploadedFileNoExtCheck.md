## Verdict

**VULNERABLE.** Line 17 calls `move_uploaded_file()` with a destination path built from the user-supplied filename (`$_FILES['avatar']['name']`) without validating the file's type or content. An attacker can upload executable files (e.g., `.php`, `.phtml`, `.shtml`) that the server may execute, leading to remote code execution.

## Source

The vulnerability occurs in lines 13-17:
```
$originalName = $_FILES['avatar']['name'];
$destination = $uploadDir . $originalName;
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

The code trusts the client-supplied filename and does not validate the file's actual content. The destination path is fully attacker-controlled via the `name` field.

## Fix

### File: MoveUploadedFileNoExtCheck.php

```php
<?php
// Handles avatar image uploads for a user profile form.

function handleAvatarUpload(): void
{
    if (!isset($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    // Allowlist of permitted MIME types for avatar images
    $allowedMimes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp'
    ];

    // Map detected MIME types to safe extensions
    $mimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp'
    ];

    // Detect the real MIME type from file content using magic bytes
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMime = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    // Validate detected MIME type against allowlist
    if (!in_array($detectedMime, $allowedMimes, true)) {
        http_response_code(400);
        echo 'Invalid file type.';
        return;
    }

    // Generate a server-side filename to prevent path traversal and extension manipulation
    $uploadDir = __DIR__ . '/uploads/avatars/';
    $filename = bin2hex(random_bytes(16)) . '.' . $mimeToExt[$detectedMime];
    $destination = $uploadDir . $filename;

    // Move the validated uploaded file to the safe destination
    if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
        http_response_code(500);
        echo 'Failed to save file.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix applies three core defences from CWE-434 remediation:

**1. Content-based validation (magic bytes):** Instead of trusting the client-supplied filename extension or `$_FILES['type']` header, the code now uses `finfo_file(FILEINFO_MIME_TYPE)` to inspect the actual file content. This detects the real type regardless of what the attacker names the file.

**2. Allowlist validation:** The detected MIME type is checked against a strict allowlist of image types (`image/jpeg`, `image/png`, `image/gif`, `image/webp`). Only these types pass; all others are rejected. This prevents upload of executable types like `application/x-php` or `application/x-executable`.

**3. Server-generated filename:** The stored filename is generated server-side using `bin2hex(random_bytes(16))` instead of using the original filename. The extension is derived from the *detected* MIME type (via `$mimeToExt` map), not the original filename. This prevents an attacker from:
   - Uploading a PHP script named `shell.php.jpg` (bypassing weak extension checks)
   - Using path traversal sequences like `../../../shell.php` in the filename
   - Controlling the final extension that the server uses for execution decisions

The fix maintains the original error handling structure while adding validation before the `move_uploaded_file()` call. The vulnerable line 17 is now preceded by mandatory type validation and uses a safe, server-controlled destination path.
