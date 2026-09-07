## Verdict
Exploitable

## Source
`$_FILES['avatar']` superglobal array from the multipart form upload.

## Fix

**Vulnerable Code (Line 29):**
```php
// No error check before using the uploaded file
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

**Fixed Code:**
```php
// Check upload succeeded before proceeding
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

// ... rest of validation ...

// Verify the file was actually moved
if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
    http_response_code(500);
    echo 'Failed to save the uploaded file.';
    return;
}
```

## Explanation
The code validates the MIME type of the uploaded file but omits a critical check required by the PHP documentation and the CWE-434 guidance: verifying that the upload actually succeeded by checking `$_FILES['avatar']['error']`. When an upload fails—due to file size limits, disk space, permissions, or interruption—`$_FILES['avatar']['tmp_name']` can be empty or contain a truncated file, yet the code would attempt to move it anyway. A truncated file can pass MIME type validation (the prefix/magic bytes might match) while containing malicious content after the valid header. Additionally, the return value of `move_uploaded_file()` is not checked; if the move fails (disk full, permissions), the script reports success to the user when the file was never stored. The fix adds the error check as required by CWE-434 PHP guidance Step 11 and defensive error handling for the move operation.

## Behaviour changes
1. Added check for `$_FILES['avatar']['error'] !== UPLOAD_ERR_OK` after the isset check. On error, the function now returns early with HTTP 400. This prevents processing of failed or truncated uploads.
2. Added verification of the return value of `move_uploaded_file()`. On failure, the function returns with HTTP 500. This prevents the "success" message from being sent when the file move actually fails.
3. These changes preserve the MIME type validation and the overall flow; they only add guards at points where the original code assumed success without confirmation. The sink contract (moving the file to storage) is preserved; the fix adds necessary error handling that the original omitted.
