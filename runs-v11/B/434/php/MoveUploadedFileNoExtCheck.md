## Verdict

This is an exploitable CWE-434 (Unrestricted Upload of File with Dangerous Type) vulnerability. The code uploads files using the client-supplied filename directly without validating file type or content, allowing an attacker to upload and execute arbitrary scripts within the webroot.

## Source

`$_FILES['avatar']['name']` — the client-supplied filename from the multipart upload request.

## Fix

**Vulnerable code (line 17):**
```php
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

**Fixed code:**
```php
function handleAvatarUpload(): void
{
    if (!isset($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    // Validate MIME type using content inspection, not client-supplied header
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        http_response_code(500);
        echo 'Server configuration error.';
        return;
    }

    $mimeType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    // Allowlist of permitted avatar MIME types
    $allowedMimeTypes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
        'image/gif'  => 'gif',
    ];

    // Validate against allowlist
    if (!isset($allowedMimeTypes[$mimeType])) {
        http_response_code(400);
        echo 'Invalid file type. Only JPEG, PNG, WebP, and GIF are allowed.';
        return;
    }

    $uploadDir = __DIR__ . '/uploads/avatars/';
    
    // Generate server-side filename from detected type
    $extension = $allowedMimeTypes[$mimeType];
    $filename = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . $filename;

    // Move file using generated, type-safe filename
    if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
        http_response_code(500);
        echo 'Failed to save avatar.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The original code trusts the client-supplied filename (`$_FILES['avatar']['name']`) directly, allowing an attacker to upload a PHP script like `shell.php` that the server will execute. The fix implements three layers of protection:

1. **Content validation**: Uses `finfo_file()` with `FILEINFO_MIME_TYPE` to detect the actual file content (magic bytes), not the client-supplied filename or `Content-Type` header, which are trivial to forge.

2. **Allowlist enforcement**: Compares the detected MIME type against a server-controlled allowlist. Only permitted image types are accepted; any mismatch is rejected immediately.

3. **Server-generated filename**: Creates a cryptographically random filename (`bin2hex(random_bytes(16))`) and derives its extension from the allowlisted MIME type map, not the client-supplied name. This prevents double-extension attacks like `image.jpg.php` and ensures the server controls how the file is executed or served.

The fixed code also checks the upload error status (`UPLOAD_ERR_OK`) before processing, validates the finfo extension is loaded (returning a 500 error if not), and checks the return value of `move_uploaded_file()` itself.

## Behaviour changes

- **Rejection of non-image uploads**: Files with MIME types outside the allowlist (e.g., `.php`, `.exe`, `.sh`) are now rejected with a 400 error.
- **Filename changes**: Uploaded files no longer retain their original names; they are stored as hex-encoded random values with safe extensions (e.g., `a3f2e1b5c6d9...jpg`).
- **Type detection mechanism**: The file type is determined by content inspection instead of trusting the client, so forged extensions or Content-Type headers no longer control the outcome.
- **Configuration dependency**: The code now requires the Fileinfo extension to be loaded; if it is absent, uploads fail with a 500 error instead of silently using an unsafe default.
