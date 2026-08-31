## Verdict

Unrestricted file upload vulnerability allowing arbitrary file types to be stored in the upload directory. The code accepts uploaded files without validating extension or MIME type, enabling attackers to upload executable files (.php, .exe, etc.) that could be accessed and executed via the web server.

## Source

```php
$uploadDir = __DIR__ . '/uploads/avatars/';
$originalName = $_FILES['avatar']['name'];
$destination = $uploadDir . $originalName;

// Vulnerable: no file type validation
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

The vulnerability is that `$originalName` is used directly from user input without validating the file extension or content type.

## Fix

```php
$uploadDir = __DIR__ . '/uploads/avatars/';
$originalName = $_FILES['avatar']['name'];

// Whitelist allowed extensions
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$fileExtension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

if (!in_array($fileExtension, $allowedExtensions, true)) {
    http_response_code(400);
    echo 'Invalid file type. Only JPG, PNG, GIF, and WebP are allowed.';
    return;
}

// Validate MIME type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mimeType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
finfo_close($finfo);

$allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
if (!in_array($mimeType, $allowedMimeTypes, true)) {
    http_response_code(400);
    echo 'Invalid MIME type. Only image files are allowed.';
    return;
}

// Use a safe filename to prevent directory traversal
$safeFilename = bin2hex(random_bytes(16)) . '.' . $fileExtension;
$destination = $uploadDir . $safeFilename;

move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

echo 'Avatar uploaded successfully.';
```

## Explanation

The fix implements a defense-in-depth approach:

1. **Extension Whitelist**: Validates that the file extension is in a hardcoded list of safe image types. This prevents uploading executable files like .php or .exe.

2. **MIME Type Validation**: Uses PHP's `finfo` to check the actual file content type (not just the extension from the filename, which can be spoofed). Only approved image MIME types are accepted.

3. **Safe Filename**: Generates a random filename using `bin2hex(random_bytes(16))` instead of using the user-supplied `$originalName`. This prevents:
   - Directory traversal attacks via specially-crafted filenames
   - Overwriting existing files
   - Executing files through double-extension tricks or null-byte injection

Together, these controls ensure that only legitimate image files can be uploaded and stored, and that they cannot be executed even if somehow accessed directly through the web server.
