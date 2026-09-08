## Verdict

exploitable

## Source

`$_FILES['avatar']['name']` at line 14, stored as `$originalName` and used to construct the destination path at line 33.

## Fix

### File: DoubleExtensionBypassesAllowlist.php

```php
<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by checking the file content
 * using magic bytes and storing with a generated filename.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    // Confirm the fileinfo extension is available
    if (!extension_loaded('fileinfo')) {
        return ['ok' => false, 'error' => 'File type detection unavailable'];
    }

    // Check file size before processing
    $maxSize = 5 * 1024 * 1024; // 5 MB
    if ($file['size'] > $maxSize) {
        return ['ok' => false, 'error' => 'File is too large'];
    }

    // Detect the real MIME type from the file's magic bytes
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    if ($detectedType === false) {
        return ['ok' => false, 'error' => 'Unable to determine file type'];
    }

    // Allowlist of permitted MIME types and their extensions
    $allowedTypes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
    ];

    if (!isset($allowedTypes[$detectedType])) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Generate a server-side filename using the detected type's extension
    $extension = $allowedTypes[$detectedType];
    $filename = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . '/' . $filename;

    // Move the file to the destination
    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        return ['ok' => false, 'error' => 'Failed to save file'];
    }

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

The original code is vulnerable to double-extension attacks because it checks only whether an allowed extension *appears anywhere* in the filename using `strpos()`. An attacker can upload a PHP file named `invoice.pdf.php` that passes validation (because `.pdf` is present) and then gets executed as PHP when stored in a web-accessible directory. The fix replaces the filename-based validation with content-based validation using `finfo_file()` to detect the actual MIME type from file magic bytes, validates the detected type against an allowlist of permitted MIME types (not extensions), and critically, generates a server-side filename using `bin2hex(random_bytes(16))` with an extension derived from the detected type. This breaks the attacker's control over the filename entirely—they can no longer choose the extension that determines how the file is executed. The file extension now always comes from the server's MIME-to-extension map, making double extensions or other filename-based bypasses impossible.

## Behaviour changes

- **Removed filename-based extension check**: The original validation (lines 16-29) that checked for allowed extensions anywhere in the filename is removed. This was the core vulnerability.
- **Added fileinfo extension check**: New code validates that PHP's fileinfo extension is loaded before attempting to use it. If unavailable, the upload is rejected. This is a defensive check per the PHP guidance.
- **Added file size validation**: New check at lines 19-22 enforces a 5 MB size limit before processing. This is secondary hardening; the original code had no size validation in the function itself.
- **File type validation changed from extension to content**: The original code trusted the filename; the new code uses `finfo_file()` to detect MIME type from the file's magic bytes (file content). This is the primary fix.
- **Filename generation changed**: The original code kept the client-supplied filename (`$originalName`); the fixed code generates a server-side filename using `bin2hex(random_bytes(16))` with an extension derived from the allowlist. This prevents any filename-based attacks.
- **Extension source changed**: The original code derived the extension from the client filename; the fixed code derives it from the server-controlled `$allowedTypes` map based on the detected MIME type.
- **Added `move_uploaded_file()` return value check**: The original code at line 36 did not check whether `move_uploaded_file()` succeeded. The fixed code now returns an error if the move fails (line 52).
- **Allowlist structure changed**: The original allowlist was a simple array of extensions (`.jpg`, `.png`, etc.); the new allowlist is a map from MIME types to extensions, enabling validation against detected content type rather than filename.
- **Error handling expanded**: The fixed code now returns distinct error messages for: upload errors, missing fileinfo extension, oversized files, undetectable file type, unsupported MIME type, and move failure. The original code only distinguished "upload failed" from "unsupported file type".

No changes to the function signature, return structure, or calling code were necessary. The function still returns a result array with `['ok' => bool, 'error' => string]` or `['ok' => true, 'path' => string]` structure as the original.
