## Verdict

Real. The code skips the required check for upload errors before attempting to process and move the uploaded file.

## Source

The vulnerable code does not validate `$_FILES['avatar']['error']` before calling `move_uploaded_file()` at line 29. PHP's file upload mechanism populates this error indicator whenever an upload fails or is interrupted, but the application proceeds as if the upload succeeded.

## Fix

Add a check for `$_FILES['avatar']['error']` immediately after verifying the file exists:

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
        echo 'File upload failed.';
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

PHP's `$_FILES` superglobal includes an `error` key for each uploaded file. This key holds an integer constant indicating whether the upload succeeded (value `0` / `UPLOAD_ERR_OK`) or failed with one of several error conditions: oversized files, partial uploads, missing temporary directories, or interruptions by PHP extensions. The check must occur before any attempt to read, validate, or move the file.

Without this guard, the code can pass a non-existent or corrupted temporary file to `finfo_file()` and `move_uploaded_file()`, leading to failed operations or—in misconfigured environments—leaving dangerous files in place. The fix adds an early guard that rejects any upload with a non-zero error code, ensuring all downstream operations work with a file that actually arrived intact.
