## Verdict
Confirmed. The code calls `move_uploaded_file()` without checking `$_FILES['avatar']['error']`, allowing processing of files that failed to upload.

## Source
```php
function handleAvatarUpload(): void
{
    if (!isset($_FILES['avatar'])) {
        http_response_code(400);
        echo 'No file uploaded.';
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

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}
```

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
        echo 'File upload error.';
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

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation
The vulnerability stems from missing validation of the upload error status before processing the file. When a file upload fails (e.g., exceeds max size, permission denied), PHP populates `$_FILES['avatar']['error']` with a non-zero value, but the `tmp_name` entry still contains a path. The code was checking the file type and calling `move_uploaded_file()` without first verifying that the upload succeeded.

The fix adds an early check: `if ($_FILES['avatar']['error'] !== UPLOAD_ERR_OK)`. This constant equals 0 only when the upload completed without errors. Any other value (UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE, UPLOAD_ERR_PARTIAL, etc.) indicates a problem and the file should not be processed further.

This check is placed immediately after verifying the file key exists and before any file processing, ensuring all validation occurs before any dangerous operations.
