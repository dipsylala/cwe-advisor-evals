## Verdict

CONFIRMED - Unrestricted file upload vulnerability. User-supplied filename is used directly without extension, type, or content validation, allowing arbitrary file upload including executable code.

## Source

Line 13 obtains the user-supplied filename directly: `$originalName = $_FILES['avatar']['name'];`

Line 14 constructs the destination path using this unvalidated filename: `$destination = $uploadDir . $originalName;`

Line 17 moves the uploaded file to this unrestricted destination without any prior validation: `move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);`

The vulnerability allows an attacker to:
- Upload a PHP file (e.g., `shell.php`) that executes as server code
- Use path traversal sequences (e.g., `../../malicious.php`) to write outside the intended directory
- Upload any file type without restriction

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
    $tmpFile = $_FILES['avatar']['tmp_name'];
    $originalName = $_FILES['avatar']['name'];
    
    // Whitelist allowed extensions
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $fileExtension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    
    if (!in_array($fileExtension, $allowedExtensions, true)) {
        http_response_code(400);
        echo 'Invalid file type.';
        return;
    }
    
    // Validate MIME type matches the extension
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $tmpFile);
    finfo_close($finfo);
    
    $allowedMimes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp'
    ];
    
    if (!isset($allowedMimes[$mimeType])) {
        http_response_code(400);
        echo 'Invalid file content.';
        return;
    }
    
    // Generate a safe filename using a hash or random ID
    $safeFilename = bin2hex(random_bytes(16)) . '.' . $allowedMimes[$mimeType];
    $destination = $uploadDir . $safeFilename;
    
    // Ensure destination stays within upload directory (prevent path traversal)
    $realPath = realpath($uploadDir);
    $realDestination = realpath(dirname($destination));
    if ($realDestination === false || strpos($realDestination, $realPath) !== 0) {
        http_response_code(400);
        echo 'Invalid upload location.';
        return;
    }
    
    if (!move_uploaded_file($tmpFile, $destination)) {
        http_response_code(500);
        echo 'Upload failed.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The remediation applies three complementary defences:

1. **Extension whitelist**: Only `.jpg`, `.jpeg`, `.png`, `.gif`, and `.webp` extensions are permitted. Comparisons use `strtolower()` to prevent bypass via case variation.

2. **MIME type validation**: The actual file content is verified using `finfo_file()` against the `FILEINFO_MIME_TYPE` constant. This ensures the file contains image data matching the declared extension, defeating attackers who simply rename executable files (e.g., `shell.php.jpg`).

3. **Safe filename generation**: The original filename is discarded entirely. A new filename is generated using `random_bytes(16)` converted to hex, eliminating both path traversal (`../`) and double-extension attacks. The mapped MIME type determines the extension, ensuring consistency between content and extension.

4. **Path containment check**: `realpath()` verifies that the final destination remains within the intended upload directory, blocking any remaining path traversal attempts.

The extension whitelist and MIME validation together ensure only image files are uploaded. Replacing the user-supplied filename with a hash prevents execution and directory traversal. If the original filename is needed for display, it should be stored in a separate database field away from the file system.
