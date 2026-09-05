## Verdict
exploitable

## Source
`$_FILES['avatar']` superglobal from multipart file upload request

## Sink
`move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)` at line 29

## Fix

**Vulnerable code (line 6-31):**
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

// SAST FINDING: CWE-434 - missing error check before move_uploaded_file
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

echo 'Avatar uploaded successfully.';
```

**Fixed code:**
```php
if (!isset($_FILES['avatar'])) {
    http_response_code(400);
    echo 'No file uploaded.';
    return;
}

// Check for upload errors before processing
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

// Check return value of move_uploaded_file
if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
    http_response_code(500);
    echo 'Failed to store upload.';
    return;
}

echo 'Avatar uploaded successfully.';
```

## Explanation

The vulnerability exists because `move_uploaded_file()` is called without checking its return value, and crucially, without first verifying that the upload succeeded via the `$_FILES['avatar']['error']` field. On a failed or partial upload, `tmp_name` can be empty or the file truncated. The type validation with `finfo_file()` may pass on corrupted data that happens to match the file signature prefix. Additionally, `move_uploaded_file()` can fail for reasons outside the application's control (permissions, disk space), but the code proceeds to report success regardless. The fix adds two checks: (1) verifying `$_FILES['avatar']['error'] === UPLOAD_ERR_OK` before any file processing, and (2) checking the return value of `move_uploaded_file()` before reporting success. This ensures only successfully uploaded files reach the validation step, and the move operation must succeed before claiming victory to the client.

## Behaviour changes

1. **Added error check before validation** - The new check on `$_FILES['avatar']['error']` rejects failed uploads early with HTTP 400, preventing truncated or empty files from reaching the type validation step. This is a blocking change that returns to the client on upload errors.

2. **Added return value check on move_uploaded_file()** - The function returns false on failure; the fix now checks this and returns HTTP 500 if the move fails. Previously, the code would report success even if the file was not actually stored, which is a silent failure mode.

These changes preserve the existing success response (HTTP 200 with success message) and use appropriate HTTP error codes (400 for upload errors, 500 for storage failures) to distinguish client-side from server-side issues.
