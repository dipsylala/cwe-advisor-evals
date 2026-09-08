## Verdict

Confirmed. `handleAvatarUpload()` moves `$_FILES['avatar']['tmp_name']` into the avatar directory without ever checking `$_FILES['avatar']['error']` or the result of `move_uploaded_file()`, and it trusts `finfo`'s MIME sniff alone to gate the "dangerous type" decision while never fixing a matching, server-chosen extension. An attacker who submits a multipart request that doesn't behave like a normal browser upload (partial/failed transfer fields, a crafted `tmp_name`, or a payload that gets stored under an attacker-influenced name) is not reliably rejected before the file lands on disk.

## Source

`$_FILES['avatar']` - populated directly from the attacker-controlled multipart/form-data request body handled by `handleAvatarUpload()`.

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

    if (!is_uploaded_file($_FILES['avatar']['tmp_name'])) {
        http_response_code(400);
        echo 'Invalid upload.';
        return;
    }

    $allowedTypes = [
        'image/png' => 'png',
        'image/jpeg' => 'jpg',
        'image/gif' => 'gif',
    ];

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    if (!isset($allowedTypes[$detectedType])) {
        http_response_code(400);
        echo 'Unsupported file type.';
        return;
    }

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $storedName = bin2hex(random_bytes(16)) . '.' . $allowedTypes[$detectedType];
    $destination = $uploadDir . $storedName;

    if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
        http_response_code(500);
        echo 'Failed to store uploaded file.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

Three gaps combined to make the move unsafe:

- **No upload-error check.** PHP populates `$_FILES['avatar']` even when the transfer didn't complete cleanly (partial upload, size-limit hit, etc.), and code that skips `$_FILES['avatar']['error'] === UPLOAD_ERR_OK` is operating on a field the runtime never promised was a genuine, complete upload. The fix rejects anything but `UPLOAD_ERR_OK` before any further processing, and additionally calls `is_uploaded_file()` to confirm `tmp_name` really is a file PHP wrote for this request via the SAPI upload mechanism, not a stale or unexpected path - this is the standard companion check to `move_uploaded_file()` and costs nothing to add.
- **Unchecked `move_uploaded_file()` return value.** The original code executes the move and unconditionally reports success even if the move failed (permissions, disk full, `is_uploaded_file()` failing internally), leaving the caller unable to distinguish a stored file from a failed one. The fix checks the return value and reports failure distinctly.
- **Client-influenced extension never fixed.** The original stores the file as a bare hex name with no extension at all, and separately trusts `finfo`'s sniffed MIME type only as a gate, not as the source of truth for what gets written to disk. The fix keeps the randomized name (so the attacker can never choose or predict the stored filename) but now derives the extension solely from the server-side `finfo` detection result via an explicit allowed-type-to-extension map, so the extension on disk always matches content PHP itself verified as one of the three permitted image types - the client's original filename or `Content-Type` header never influences what gets written.

Together these changes make the type check the thing that actually gates what reaches disk, and make sure a failed or non-genuine upload is rejected before `move_uploaded_file()` is ever called.
