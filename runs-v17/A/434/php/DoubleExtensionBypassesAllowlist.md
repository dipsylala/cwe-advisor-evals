## Verdict
Vulnerability confirmed. The validation logic uses `strpos()` to check if an allowed extension appears anywhere in the filename, which allows double-extension bypass attacks (e.g., `shell.php.jpg` passes validation but executes as PHP). The fix must validate only the final extension.

## Source
The vulnerable code on line 36 calls `move_uploaded_file()` with a destination path built from `$originalName` without proper extension validation. Lines 16-25 perform the validation using `strpos(strtolower($originalName), $ext)`, which detects any occurrence of an allowed extension rather than the final extension of the file.

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

    // Only allow filenames with approved image extensions as the final
    // extension to prevent double-extension bypass attacks.
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
    $fileExtension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    
    if (!in_array($fileExtension, $allowedExtensions, true)) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Keep the client's original filename (extension chain and all) so
    // the avatar keeps a recognizable name in the uploads listing.
    $destination = $uploadDir . '/' . $originalName;

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
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
The remediation replaces the vulnerable substring-matching logic with a check of only the final file extension using `pathinfo(..., PATHINFO_EXTENSION)`. This prevents double-extension bypass attacks because:

1. `pathinfo($originalName, PATHINFO_EXTENSION)` extracts only the rightmost extension after the final dot, so `shell.php.jpg` yields `jpg` (the actual extension the server will execute), not `jpg` hidden in the middle.
2. `in_array($fileExtension, $allowedExtensions, true)` performs strict comparison against the allowlist without the leading dot and without substring matching.
3. Extensions are normalized to lowercase before comparison to prevent case-based bypasses (`shell.php.JPG`).

The original allowlist is updated to store extensions without the leading dot for cleaner comparison logic, matching the output of `pathinfo()`.
