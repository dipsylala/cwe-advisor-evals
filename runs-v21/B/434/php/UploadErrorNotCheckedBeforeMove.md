## Verdict

CONFIRMED - The code validates the file's MIME type against an allowlist using `finfo_file()` and generates a server-side filename, but it omits the required check of `$_FILES['avatar']['error']` before calling `move_uploaded_file()`. On a failed or partial upload, `tmp_name` can be empty or the file truncated; a truncated file may still pass the MIME type check. The code also does not verify that the fileinfo extension is available before using it, and does not append an extension to the stored filename derived from the detected type.

## Source

The vulnerability is in the upload handler's failure to validate the upload operation before processing the temporary file. The code flow:
1. Checks if `$_FILES['avatar']` key exists (line 6)
2. Loads fileinfo and checks MIME type against allowlist (lines 14-22)
3. Generates filename and calls `move_uploaded_file()` (lines 24-29) ← **Missing `error` check**

When the upload fails (e.g., POST size limit exceeded, partial transfer, disk full), `$_FILES['avatar']['error']` is set to a non-zero constant (`UPLOAD_ERR_FORM_SIZE`, `UPLOAD_ERR_PARTIAL`, etc.), but the code proceeds as if the upload succeeded, potentially processing a truncated or invalid file.

## Fix

### File: UploadErrorNotCheckedBeforeMove.php

```php
<?php
// Handles avatar image uploads for a user profile form.

function handleAvatarUpload(): void
{
    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'Upload service misconfigured.';
        return;
    }

    if (!isset($_FILES['avatar'])) {
        http_response_code(400);
        echo 'No file uploaded.';
        return;
    }

    if ($_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    $allowedTypes = ['image/png', 'image/jpeg', 'image/gif'];
    $mimeToExt = [
        'image/png' => '.png',
        'image/jpeg' => '.jpg',
        'image/gif' => '.gif',
    ];

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    if (!in_array($detectedType, $allowedTypes, true)) {
        http_response_code(400);
        echo 'Unsupported file type.';
        return;
    }

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $ext = $mimeToExt[$detectedType];
    $storedName = bin2hex(random_bytes(16)) . $ext;
    $destination = $uploadDir . $storedName;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix adds three critical safeguards:

1. **Extension availability check (lines 5-9)**: Verifies that the fileinfo extension is loaded before attempting to use `finfo_open()`. If missing, it terminates early with a 500 error rather than allowing a fatal `Error` to propagate or allowing the validation to silently fail.

2. **Upload error validation (lines 17-21)**: Checks `$_FILES['avatar']['error']` against `UPLOAD_ERR_OK` before processing the file. This ensures the file was completely and successfully transferred to the temporary directory. Any upload error (partial transfer, size exceeded, permissions, etc.) causes immediate rejection rather than attempting to move a truncated or corrupted file.

3. **Type-derived extension mapping (lines 23-30, lines 42-45)**: Creates a map from allowed MIME types to their canonical extensions. The generated storage filename now includes the extension derived from the *detected* type, not from the client-supplied name, preventing an attacker from choosing the execution context by manipulating the original filename extension.

The fix preserves the existing secure patterns (random filename generation via `bin2hex(random_bytes(16))`, allowlist-based MIME type validation, server-side filename construction) while closing the gaps that allowed truncated uploads and extension manipulation.

## Behaviour changes

- Uploads with non-zero `error` codes are now rejected before file processing, preventing truncated-file attacks.
- Missing fileinfo extension causes early termination with clear error messaging instead of a fatal error during validation.
- The stored filename now includes an extension (e.g., `.png`) derived from the detected MIME type, ensuring proper handling on future retrieval, and preventing the attacker from controlling the file's execution context through the original extension.
- File size is still checked in `php.ini` via `upload_max_filesize` and `post_max_size`, but the error from a size violation now triggers the rejection at line 19-21 instead of bypassing validation.
