## Verdict

The upload is not validated for transmission errors before processing. `$_FILES['avatar']['error']` must be checked for `UPLOAD_ERR_OK` before `move_uploaded_file()` is called.

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

move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

## Fix

Add an error status check immediately after verifying the file is present:

```php
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

move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

## Explanation

The PHP `$_FILES` superglobal contains an `error` key for each uploaded file that holds a status code indicating whether the upload succeeded. Possible values include `UPLOAD_ERR_OK` (0, success) and error codes such as `UPLOAD_ERR_INI_SIZE`, `UPLOAD_ERR_FORM_SIZE`, `UPLOAD_ERR_PARTIAL`, `UPLOAD_ERR_NO_FILE`, and `UPLOAD_ERR_NO_TMP_DIR`.

The original code validates the MIME type but does not check the error code. This means a file that failed to upload can still reach `move_uploaded_file()`, potentially causing silent failures or leaving an incomplete temporary file in place. Checking `$_FILES['avatar']['error'] !== UPLOAD_ERR_OK` guards against transmission errors and ensures only valid uploads are processed.

This check must precede all other file operations and should reject the request with a 400 status and a clear error message when the upload fails.
