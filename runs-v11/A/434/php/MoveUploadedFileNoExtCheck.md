## Verdict

The code is vulnerable to CWE-434 (Unrestricted Upload of File with Dangerous Type) because it accepts the client-supplied filename directly without validating the file extension or verifying the actual file type, allowing an attacker to upload executable files or other dangerous content.

## Source

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

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $originalName = $_FILES['avatar']['name'];
    $destination = $uploadDir . $originalName;

    // VULNERABILITY: No validation of file extension or type
    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

The vulnerability at line 17 is the unrestricted use of `$_FILES['avatar']['name']` to build the destination path without checking the file extension or actual file content type.

## Fix

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

    $uploadDir = __DIR__ . '/uploads/avatars/';
    
    // Whitelist of allowed image extensions
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    
    // Get file extension from uploaded filename
    $fileExt = strtolower(pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION));
    
    // Validate extension against whitelist
    if (!in_array($fileExt, $allowedExtensions, true)) {
        http_response_code(400);
        echo 'Invalid file type. Only image files are allowed.';
        return;
    }
    
    // Validate actual MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!in_array($mimeType, $allowedMimes, true)) {
        http_response_code(400);
        echo 'File content does not match an allowed image type.';
        return;
    }
    
    // Generate a safe filename using a random identifier and the validated extension
    $safeFilename = bin2hex(random_bytes(16)) . '.' . $fileExt;
    $destination = $uploadDir . $safeFilename;

    // Now upload is safe: extension validated, MIME type validated, filename sanitized
    if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
        http_response_code(500);
        echo 'Failed to move uploaded file.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix addresses CWE-434 through three layers of defense:

1. **Extension Whitelisting**: Extract the file extension and check it against a whitelist of allowed image types (`jpg`, `jpeg`, `png`, `gif`, `webp`). This prevents executable extensions like `.php`, `.exe`, `.sh`, or `.phtml` from being uploaded.

2. **MIME Type Validation**: Use `finfo_file()` to inspect the actual file content and verify it matches an allowed image MIME type. This prevents attackers from uploading executable code disguised with an image extension (e.g., a PHP script renamed to `.jpg`).

3. **Safe Filename Generation**: Instead of using the client-supplied filename, generate a random hex identifier combined with the validated extension. This prevents:
   - Directory traversal attempts (e.g., `../../../etc/passwd`)
   - Predictable filenames that could be directly accessed
   - Confusion from special characters in the original filename

All validation happens before `move_uploaded_file()` is called, ensuring only safe, verified files are stored. The error handling provides clear feedback when validation fails.
