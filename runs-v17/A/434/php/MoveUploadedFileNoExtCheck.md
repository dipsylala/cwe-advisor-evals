## Verdict

The finding is confirmed. The code accepts and stores uploaded files without validating their type, allowing an attacker to upload executable files (such as PHP scripts) that can then be executed by the web server, leading to arbitrary code execution.

## Source

**File:** MoveUploadedFileNoExtCheck.php  
**Lines:** 13–17

The vulnerability is in the use of the unsanitized filename from `$_FILES['avatar']['name']` directly as the destination path, combined with the absence of any file-type validation before calling `move_uploaded_file()`.

```php
$originalName = $_FILES['avatar']['name'];
$destination = $uploadDir . $originalName;
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

An attacker can upload a file named `shell.php` or `shell.php.jpg`, and if stored in a web-accessible directory, the server will execute it.

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

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $originalName = $_FILES['avatar']['name'];
    
    // Validate file extension against allowlist
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
    $fileExtension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    
    if (!in_array($fileExtension, $allowedExtensions, true)) {
        http_response_code(400);
        echo 'Invalid file type. Only JPG, PNG, and GIF are allowed.';
        return;
    }
    
    // Use a safe filename to prevent other attacks
    $safeFilename = bin2hex(random_bytes(16)) . '.' . $fileExtension;
    $destination = $uploadDir . $safeFilename;

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix introduces two layers of protection against CWE-434:

1. **File extension validation:** Before moving the uploaded file, the code extracts the file extension using `pathinfo()` and validates it against an allowlist of safe image types (`jpg`, `jpeg`, `png`, `gif`). If the extension is not in the allowlist, the upload is rejected with a 400 error. This prevents an attacker from uploading executable files like `.php`, `.phtml`, `.exe`, or other dangerous types.

2. **Safe filename generation:** Instead of using the user-supplied filename directly, the code generates a cryptographically random filename using `bin2hex(random_bytes(16))`. This prevents:
   - Directory traversal attacks (e.g., `../../shell.php`)
   - Double-extension bypass attempts (e.g., `shell.php.jpg`)
   - Overwriting existing files
   - Execution of uploaded scripts via predictable paths

The `strtolower()` call ensures case-insensitive comparison, so `.PHP`, `.pHp`, and `.php` are all rejected. The `in_array(..., true)` uses strict type checking to prevent type juggling vulnerabilities.

This approach follows CWE-434 remediation best practices: reject based on an allowlist of known-safe types rather than a denylist of dangerous ones, validate before moving the file into the web root, and use a safe storage strategy that decouples the stored filename from the uploaded one.
