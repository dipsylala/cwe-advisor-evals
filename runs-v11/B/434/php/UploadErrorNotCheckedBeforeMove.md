## Verdict

exploitable

## Source

`$_FILES['avatar']` superglobal (line 6), specifically the error state that is never validated.

## Fix

**Vulnerable Code (line 6–29):**
```php
if (!isset($_FILES['avatar'])) {
    http_response_code(400);
    echo 'No file uploaded.';
    return;
}

$allowedTypes = ['image/png', 'image/jpeg', 'image/gif'];

$finfo = finfo_open(FILEINFO_MIME_TYPE);
$detectedType = finfo_file($finfo, $_FILES['avatar']['tmp_name']); // VULNERABLE: no error check yet
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
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination); // VULNERABLE: upload error never checked
```

**Fixed Code:**
```php
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
```

## Explanation

The vulnerability exists because the code validates the uploaded file's MIME type via `finfo_file()` but never checks whether the upload operation itself succeeded. PHP's `$_FILES['x']['error']` element indicates the outcome of the upload (UPLOAD_ERR_OK = 0, UPLOAD_ERR_PARTIAL = 3, UPLOAD_ERR_NO_FILE = 4, etc.). On a partial or failed upload, `tmp_name` can be empty or contain a truncated file. A truncated file may still pass the MIME type check if it starts with valid magic bytes, allowing corrupted or partially uploaded content to be stored and served. The fix adds an explicit check of `$_FILES['avatar']['error']` immediately after verifying the file was provided, rejecting any upload that did not complete successfully. This ensures `tmp_name` contains a complete, valid file before any further processing.

## Behaviour changes

none
