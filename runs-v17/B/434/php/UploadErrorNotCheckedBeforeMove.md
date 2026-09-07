## Verdict

Exploitable

## Source

`$_FILES['avatar']` superglobal array from the client's multipart form submission

## Fix

### File: UploadErrorNotCheckedBeforeMove.php

```php
<?php
// Handles avatar image uploads for a user profile form.

function handleAvatarUpload(): void
{
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

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    if (!in_array($detectedType, $allowedTypes, true)) {
        http_response_code(400);
        echo 'Unsupported file type.';
        return;
    }

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $storedName = bin2hex(random_bytes(16));
    $destination = $uploadDir . $storedName;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The vulnerability was the absence of an upload-error check before processing the file. The code checked whether the `avatar` key existed in `$_FILES` but did not verify the upload's success status via `$_FILES['avatar']['error']`. When an upload fails or is partial, `error` is set to a non-zero constant (such as `UPLOAD_ERR_NO_FILE`, `UPLOAD_ERR_PARTIAL`, or `UPLOAD_ERR_NO_TMP_DIR`), and `tmp_name` may be empty or contain truncated/invalid data. A truncated file can still carry the correct magic bytes for a permitted MIME type and pass the `finfo_file()` check, allowing corrupted or attacker-crafted content to bypass validation. The fix adds an explicit check that `$_FILES['avatar']['error'] === UPLOAD_ERR_OK` immediately after verifying the key exists, ensuring the upload succeeded before any file operations are attempted.

## Behaviour changes

Added the error status check at line 12-16 before reading the uploaded file. The check exits early with a 400 response if the upload failed, which prevents the finfo_file() call and move_uploaded_file() from operating on invalid file data. This is a defensive addition with no impact on successful uploads—the validator contract and sink behavior remain unchanged for valid uploads.
