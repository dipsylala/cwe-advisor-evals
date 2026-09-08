## Verdict
The vulnerability is confirmed. The code uses `strpos()` to check if an allowed extension appears anywhere in the filename, which permits double-extension bypasses. An attacker can upload "shell.php.jpg" and the code accepts it because ".jpg" is present in the string. A web server may then execute the file as PHP, bypassing the extension allowlist.

## Source
The vulnerability is at line 36 where `move_uploaded_file()` stores a file with an unsanitized filename. The root cause is lines 20–24, which check for an allowed extension anywhere in the name rather than validating the true file extension (the one after the final dot).

## Fix
### File: DoubleExtensionBypassesAllowlist.php

```php
<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by checking the filename against
 * an allowlist of image extensions before storing the file.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    $originalName = $file['name'];

    // Extract the true file extension (the extension after the final dot only).
    // pathinfo() with PATHINFO_EXTENSION extracts only the final extension,
    // preventing double-extension bypasses like "shell.php.jpg".
    $fileExtension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    
    // Only allow specific image file extensions.
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
    
    if (!in_array($fileExtension, $allowedExtensions, true)) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Generate a safe filename using a hash to prevent extension-based attacks
    // and eliminate the risk of double extensions, path traversal, or other
    // naming-based exploits. The hash is derived from the temporary filename
    // and timestamp to ensure uniqueness.
    $safeFilename = hash('sha256', $file['tmp_name'] . time()) . '.' . $fileExtension;
    $destination = $uploadDir . '/' . $safeFilename;

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) was reported here. Fixed by validating only the final extension and using a hash-based safe filename.
    move_uploaded_file($file['tmp_name'], $destination);

    return ['ok' => true, 'path' => $destination];
}

$result = handleAvatarUpload($_FILES['avatar'], __DIR__ . '/uploads');
if (!$result['ok']) {
    http_response_code(400);
    echo json_encode(['error' => $result['error']]);
    exit;
}

echo json_encode(['path' => $result['path']]);
```

## Explanation
The fix addresses CWE-434 by making two key changes:

1. **Correct extension validation**: Replace `strpos()` with `pathinfo($originalName, PATHINFO_EXTENSION)` to extract only the final extension in the filename. This eliminates the double-extension bypass where "shell.php.jpg" would pass the old check.

2. **Safe filename generation**: Instead of storing the file under the original (potentially malicious) name, generate a hash-based filename. This removes any attack surface based on filename composition, double extensions, or directory traversal attempts. The hash is derived from the temporary file location and current time to ensure uniqueness.

The combination prevents attackers from uploading executable files disguised as images, and ensures that even if a filename is manipulated, the stored file cannot be exploited through naming tricks.
