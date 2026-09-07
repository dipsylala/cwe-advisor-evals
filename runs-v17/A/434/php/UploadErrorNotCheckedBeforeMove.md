## Verdict
The code is vulnerable to CWE-434 because it calls `move_uploaded_file()` without first checking the upload error status in `$_FILES['avatar']['error']`. An upload can fail for multiple reasons (exceeding size limits, partial transfer, no tmp directory, etc.) before reaching the MIME type validation, and the code proceeds to move an invalid or incomplete file anyway.

## Source
```php
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
```

The `isset()` check on line 6 only verifies that the key exists; it does not check the upload error field.

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

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation
The vulnerability is fixed by adding an error check immediately after verifying the file array exists. Line 12-16 now check `$_FILES['avatar']['error']` against `UPLOAD_ERR_OK` (the constant value 0), which is the only success state for a file upload. If the error field contains any other value, it indicates a failure during the PHP upload process itself (e.g., exceeding size limits, partial transfer, temporary directory issues), and the function rejects the request before attempting to move the incomplete or invalid file.

This check is placed early in the function, before any file operations or MIME type inspection, because upload errors are a precondition to having a usable temporary file at all. The subsequent MIME type validation remains in place as a defence-in-depth measure to reject files that passed the upload phase but do not match the allowed content types.
