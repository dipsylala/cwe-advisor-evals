## Verdict

- **cwe_id**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **location**: `UploadErrorNotCheckedBeforeMove.php`, line 29 (`move_uploaded_file()` call)
- **verdict**: exploitable
- **confidence**: medium

## Source

- **Source**: `$_FILES['avatar']` - the multipart upload superglobal populated from the incoming HTTP request. Specifically `$_FILES['avatar']['tmp_name']` (fed into `finfo_file()` and then into `move_uploaded_file()`) and `$_FILES['avatar']['error']` (never read at all in the original code).
- **Sink**: `move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)` at line 29.
- **Data flow**: The request arrives at `handleAvatarUpload()`. The code checks only that the `avatar` key exists (`isset($_FILES['avatar'])`), then immediately runs `finfo_file()` against `tmp_name` and gates on the detected MIME type against an image allowlist. It never inspects `$_FILES['avatar']['error']`. On a non-`UPLOAD_ERR_OK` result (most commonly `UPLOAD_ERR_PARTIAL`, produced when the client deliberately aborts the request body after PHP has already written the partial upload to a temp file), `tmp_name` still points at a real, non-empty temporary file containing only the bytes the attacker chose to send. `finfo_file()` performs magic-byte detection - it inspects a leading prefix of the file, not the whole content or its structural validity - so a temp file consisting of a valid image header followed by attacker payload, or truncated before the point PHP would otherwise reject it as incomplete, still reports as `image/png`/`image/jpeg`/`image/gif` and passes the allowlist check. `move_uploaded_file()` then persists that file to `$uploadDir` under a server-generated name. The error-status gap is exactly what lets a request PHP itself flagged as failed/partial reach the same sink as a normal successful upload.

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

The fix adds a single gate - `$_FILES['avatar']['error'] !== UPLOAD_ERR_OK` - immediately after the existing "was a file sent at all" check and before any content is read or validated. This closes the gap identified in the data-flow trace: a request PHP itself marked as partial or otherwise failed (`tmp_name` non-empty but containing only attacker-controlled partial bytes) is now rejected with a 400 before `finfo_file()` ever inspects it, so a truncated file can no longer ride the same magic-byte check that legitimate complete uploads rely on and reach `move_uploaded_file()`. It leaves the existing content-based allowlist check (`finfo_file()` against `image/png`/`image/jpeg`/`image/gif`), the server-generated storage filename (`bin2hex(random_bytes(16))`), and the sink call itself untouched, since those controls were already present and correct for the complete-upload case; the missing control was specifically the upload-status check the PHP guidance calls out (`cwe/434/php/INDEX.md`: "Confirm the upload succeeded before reading it... a truncated file may still pass a prefix-based type check").

**Library recommendation**: none - the fix uses only PHP core (`$_FILES`, the `UPLOAD_ERR_OK` constant already used implicitly by PHP's upload machinery) and the Fileinfo functions already present in the original code. No dependency change is required.

**Verification**: `php -l` was run against the fixed file (PHP 8.5.8 CLI) and returned "No syntax errors detected". No project test suite is present in the case directory to exercise further.

## Behaviour changes

- **Added early-return branch**: a request whose `$_FILES['avatar']['error']` is not `UPLOAD_ERR_OK` (e.g. `UPLOAD_ERR_PARTIAL`, `UPLOAD_ERR_NO_FILE` with the key still set, `UPLOAD_ERR_INI_SIZE`, etc.) now gets HTTP 400 and the message "Upload failed." instead of proceeding into the type check. This is the intended closure of the weakness, not a side effect - it only changes behavior for uploads PHP itself already flagged as unsuccessful; a normal, fully-received upload (`UPLOAD_ERR_OK`) follows the exact same path as before, unchanged.
- No other difference from the original: the allowlist values, the `finfo_open`/`finfo_file`/`finfo_close` calls, the storage directory, the random filename generation, the `move_uploaded_file()` call and its arguments, and the success message are all identical to the original file.
