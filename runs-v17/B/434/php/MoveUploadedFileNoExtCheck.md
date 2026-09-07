## Verdict

exploitable

## Source

`$_FILES['avatar']` superglobal (user-supplied file upload), specifically `$_FILES['avatar']['name']` and `$_FILES['avatar']['tmp_name']`

## Fix

### File: MoveUploadedFileNoExtCheck.php

```php
<?php
// Handles avatar image uploads for a user profile form.

function handleAvatarUpload(): void
{
    if (!isset($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    // Verify fileinfo extension is available
    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'Server configuration error.';
        return;
    }

    // Detect actual MIME type from file content using magic bytes
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    // Allowlist of permitted MIME types for avatars with safe extensions
    $allowedMimeTypes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp',
    ];

    // Validate against the detected MIME type
    if (!isset($allowedMimeTypes[$mimeType])) {
        http_response_code(400);
        echo 'File type not allowed.';
        return;
    }

    // Generate a secure server-side filename
    $extension = $allowedMimeTypes[$mimeType];
    $filename = bin2hex(random_bytes(16)) . '.' . $extension;

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $destination = $uploadDir . $filename;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The original code constructs the destination path from `$_FILES['avatar']['name']`, which is the client-supplied filename from the multipart request. An attacker can set this to any value, including `evil.php` or `shell.phtml`, allowing them to upload and execute arbitrary server-side code if the upload directory is within the webroot and script execution is enabled. The fix eliminates this by: (1) validating the actual file content using `finfo_file()` to detect the true MIME type from magic bytes rather than trusting the client-supplied `Content-Type` header or filename extension; (2) allowlisting only permitted MIME types (`image/jpeg`, `image/png`, `image/gif`, `image/webp`) with their corresponding safe extensions; (3) rejecting any file whose detected MIME type is not in the allowlist; and (4) generating a cryptographically random server-side filename using `bin2hex(random_bytes(16))` and deriving its extension from the validated MIME type through the allowlist map, breaking the taint chain and preventing the attacker from controlling the stored filename.

## Behaviour changes

- **New validation gate**: `extension_loaded('fileinfo')` check added. If the Fileinfo extension is not loaded, execution returns HTTP 500 with an error message instead of proceeding. This is correct because `finfo_file()` is required for the fix and will cause a fatal error if called when the extension is missing; the check surfaces the configuration error immediately rather than silently failing. (Reason: ensures type validation is actually possible before attempting to use it.)
- **New validation**: Rejects files whose detected MIME type is not in the `$allowedMimeTypes` allowlist, returning HTTP 400. The original code accepted any file regardless of content. (Reason: blocks dangerous file types at the source.)
- **Filename transformation**: The stored filename is now a server-generated value (`bin2hex(random_bytes(16)) . '.' . $extension`) instead of the user-supplied `$_FILES['avatar']['name']`. (Reason: prevents path traversal and ensures the file cannot be directly named with a dangerous extension by the attacker.)
- **Extension derivation**: The file extension stored on disk now comes from the validated MIME type via the allowlist map, not from the client-supplied name. (Reason: ensures the stored file extension matches its actual content, preventing double-extension attacks and enforcement of execution policies by the server.)

