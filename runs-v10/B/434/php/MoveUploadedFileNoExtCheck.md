## Verdict

The code is vulnerable. The upload handler accepts any file and stores it using the client-supplied filename directly in a web-accessible directory, allowing an attacker to upload an executable script (e.g., `.php`), a web shell, or other dangerous content that the server will execute or serve directly.

## Source

`$_FILES['avatar']['name']` is read from the client's request (line 13) and used directly as the storage filename (line 14). The file is then written to `$uploadDir` with `move_uploaded_file()` (line 17). The upload directory (`__DIR__ . '/uploads/avatars/'`) is typically within the webroot and script-executable.

## Fix

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

    // Validate file content using Fileinfo extension
    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'Upload validation unavailable.';
        return;
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        http_response_code(500);
        echo 'Upload validation failed.';
        return;
    }

    $detectedMimeType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    // Allowlist of permitted image MIME types for avatars
    $allowedMimeTypes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
    ];

    if (!in_array($detectedMimeType, $allowedMimeTypes, true)) {
        http_response_code(400);
        echo 'Invalid file type.';
        return;
    }

    // Map MIME types to file extensions (server-controlled)
    $mimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];

    $extension = $mimeToExt[$detectedMimeType];

    // Generate a server-side filename
    $storedFilename = bin2hex(random_bytes(16)) . '.' . $extension;

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $destination = $uploadDir . $storedFilename;

    if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
        http_response_code(500);
        echo 'Upload failed.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix closes CWE-434 by enforcing three controls:

1. **Content validation**: `finfo_file()` inspects the file's magic bytes to detect its real MIME type, independent of the client-supplied filename or `Content-Type` header. The check for `extension_loaded('fileinfo')` ensures the Fileinfo extension is available; without it, `finfo_open()` would trigger a fatal error rather than return `false`.

2. **Allowlist of permitted types**: The detected MIME type is validated against a whitelist (`$allowedMimeTypes`) of safe image types suitable for user avatars. Any file that does not match is rejected with a 400 error.

3. **Server-generated filename**: Instead of using the client-supplied `$_FILES['avatar']['name']`, the code generates a random filename server-side using `bin2hex(random_bytes(16))`. The extension is sourced from the allowlist map (`$mimeToExt`), not from the original filename, so an attacker cannot bypass the type check by uploading `shell.jpg.php`.

Together, these prevent an attacker from uploading and executing arbitrary code, HTML, SVG, or other active content in the avatars directory. The file type is verified by actual content, not by user-controlled metadata.

## Behaviour changes

- Files that do not match the allowlist of image types are rejected (previously accepted).
- Stored files are renamed to random server-generated names (previously kept original filename).
- The handler now returns a 500 error if the Fileinfo extension is not available (prevents silent bypass).
- All non-image uploads return a 400 error with "Invalid file type." message (previously uploaded and served).
