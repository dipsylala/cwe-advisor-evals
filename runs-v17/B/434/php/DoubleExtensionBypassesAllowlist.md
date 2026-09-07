## Verdict

Exploitable

## Source

`$_FILES['avatar']['name']` (client-supplied filename from the multipart request) propagates to the storage path on line 33, and the file content from `$_FILES['avatar']['tmp_name']` is written to that path via `move_uploaded_file()` on line 36 without validation of actual content.

## Fix

### File: DoubleExtensionBypassesAllowlist.php

```php
<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by validating actual content and
 * storing with a server-generated filename.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    // Verify the upload succeeded before reading the file
    if (empty($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return ['ok' => false, 'error' => 'Invalid upload'];
    }

    // Map allowed MIME types to file extensions
    $allowedMimeTypes = [
        'image/jpeg' => '.jpg',
        'image/png' => '.png',
        'image/gif' => '.gif'
    ];

    // Detect actual MIME type from file content using Fileinfo
    if (!extension_loaded('fileinfo')) {
        return ['ok' => false, 'error' => 'System configuration error'];
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    // Validate against allowlist of MIME types
    if ($detectedMimeType === false || !isset($allowedMimeTypes[$detectedMimeType])) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Get the extension from the detected MIME type
    $extension = $allowedMimeTypes[$detectedMimeType];

    // Generate a server-side filename to prevent extension and traversal attacks
    $storedFilename = bin2hex(random_bytes(16)) . $extension;
    $destination = $uploadDir . '/' . $storedFilename;

    // Store the file with the generated name
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

The original code checked only whether an allowed extension string appeared anywhere in the client-supplied filename using `strpos()`, then stored the file with that original name intact. This allows a double-extension bypass: an attacker uploads `shell.php.jpg`, which passes the check because `.jpg` exists in the string, but is stored and potentially executed as PHP depending on server configuration.

The fix replaces the filename-based check with content-based validation using `finfo_file()` to detect the actual MIME type from the file's magic bytes. The detection result is checked against an allowlist of permitted MIME types (`image/jpeg`, `image/png`, `image/gif`). Critically, a server-generated filename is used for storage instead of the original client-supplied name, deriving the extension from the detected MIME type through a fixed allowlist map. This eliminates the ability to bypass the check via double extensions or path traversal sequences in the original filename, because the attacker's filename is never used in the storage path.

## Behaviour changes

- Replaced extension-string presence check (`strpos()` on client-supplied filename) with content validation (`finfo_file()` on the uploaded file's actual bytes). This is a stricter gate that rejects mismatched extension/content pairs.
- Added `is_uploaded_file()` check to confirm the file came from the upload mechanism before reading it, preventing exploitation through pre-positioned files.
- Added `extension_loaded('fileinfo')` verification to detect missing Fileinfo extension at runtime rather than allowing the function to fail fatally.
- Replaced client-supplied filename with server-generated name (`bin2hex(random_bytes(16))`) for storage, eliminating filename-based attacks.
- Derived stored extension from detected MIME type (via `$allowedMimeTypes` map) rather than trusting client input.
- These changes alter the response: the `path` returned now contains a server-generated filename (e.g., `uploads/a1b2c3d4e5f6g7h8.jpg`) instead of the original filename. If the application or client expects the original filename to be preserved in the storage path, that expectation must be reconsidered — preserving it would reintroduce the vulnerability.

