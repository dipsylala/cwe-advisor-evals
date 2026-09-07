## Verdict

exploitable

## Source

`$_FILES['avatar']['tmp_name']` from the multipart form upload, accessed without prior validation of the upload status.

## Fix

**Vulnerable code** (line 29):

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

// PROBLEM: No check for $_FILES['avatar']['error'] before calling move_uploaded_file()
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

**Fixed code**:

```php
if (!isset($_FILES['avatar'])) {
    http_response_code(400);
    echo 'No file uploaded.';
    return;
}

// Verify the upload succeeded
if ($_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo 'File upload error: ' . $_FILES['avatar']['error'];
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

// Now safe - upload confirmed to have succeeded
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

## Explanation

The vulnerable code validates the uploaded file's MIME type but omits a critical check: verifying that the upload itself succeeded via `$_FILES['avatar']['error']`. When an upload fails or is partial, `$_FILES['avatar']['tmp_name']` may reference an empty file or a truncated upload. A truncated file with a valid file header (magic bytes) can pass the `finfo_file()` MIME type check, and calling `move_uploaded_file()` on such a file persists the incomplete/invalid upload. The fix adds an early check: `if ($_FILES['avatar']['error'] !== UPLOAD_ERR_OK)` immediately after verifying the key exists, rejecting the upload before any file operations proceed. This ensures that `move_uploaded_file()` is only called on uploads that PHP confirms are complete and valid.

## Behaviour changes

The fix introduces an additional return path when the upload fails (e.g., `UPLOAD_ERR_PARTIAL`, `UPLOAD_ERR_NO_FILE`, `UPLOAD_ERR_CANT_WRITE`). This prevents truncated or failed uploads from being processed. On success (`UPLOAD_ERR_OK`), execution flow and behavior are unchanged from the original; the file is validated and moved identically. The error response uses `http_response_code(400)` and outputs the error code, consistent with existing error handling in the function.

