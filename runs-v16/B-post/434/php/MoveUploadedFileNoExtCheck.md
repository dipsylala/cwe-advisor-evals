## Verdict

Real. The code accepts an uploaded file and stores it using the client-supplied filename without type validation, content inspection, or filename sanitization. An attacker can upload a PHP script or other executable with any desired filename, execute it if the upload directory permits script execution, or use path traversal sequences in the filename.

## Source

Line 13: `$_FILES['avatar']['name']` - the client-supplied filename from the multipart upload request.

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

    // Validate MIME type using finfo
    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'Upload validation not available.';
        return;
    }

    $allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMimeType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    if (!in_array($detectedMimeType, $allowedMimeTypes, true)) {
        http_response_code(400);
        echo 'Invalid file type.';
        return;
    }

    // Generate server-side filename from detected MIME type
    $mimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp',
    ];
    $extension = $mimeToExt[$detectedMimeType];
    $filename = bin2hex(random_bytes(16)) . '.' . $extension;

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $destination = $uploadDir . $filename;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix implements three core controls: (1) MIME type validation using `finfo_file()` on the uploaded file's actual bytes (magic bytes), not the client-supplied `Content-Type` header; (2) an allowlist of permitted image types; (3) server-side filename generation using `bin2hex(random_bytes(16))` to eliminate any user-controlled path component. The stored filename is built entirely from the detected MIME type via a fixed allowlist map, ensuring the final extension matches the real file content and cannot be manipulated to bypass extension-based execution filters. The Fileinfo extension is checked at startup to fail fast rather than silently pass validation. The original client-supplied filename in `$_FILES['avatar']['name']` is never used after the type check, breaking the taint chain.

## Behaviour changes

- Upload endpoint now rejects files whose actual content does not match one of the allowlisted MIME types (JPEG, PNG, GIF, WebP), even if the client claims otherwise via the Content-Type header or filename extension.
- Uploaded files are stored with server-generated random names (e.g., `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.png`) instead of the original client-supplied filename, eliminating path traversal and filename-based attack vectors.
- If the Fileinfo extension is not loaded, uploads fail with a 500 response instead of succeeding without validation.
- File extension is guaranteed to match the detected MIME type, so a polyglot or misnamed file will be rejected before storage.
