## Verdict

The code is vulnerable to CWE-434. The uploaded file is stored using the client-supplied filename without validating its extension or type, allowing an attacker to upload executable files (e.g., `.php`) that could be executed by the web server if placed in a web-accessible directory.

## Source

Line 17 in `MoveUploadedFileNoExtCheck.php`:
```php
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

The destination path (line 14) is constructed from the unsanitized `$_FILES['avatar']['name']`:
```php
$destination = $uploadDir . $originalName;
```

This allows an attacker to control the file extension and name.

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

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $originalName = $_FILES['avatar']['name'];
    
    // Validate file extension against a whitelist
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
    $fileExtension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    
    if (!in_array($fileExtension, $allowedExtensions, true)) {
        http_response_code(400);
        echo 'Invalid file type.';
        return;
    }
    
    // Generate a safe filename to prevent name-based attacks
    $safeFilename = bin2hex(random_bytes(16)) . '.' . $fileExtension;
    $destination = $uploadDir . $safeFilename;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix applies two critical controls:

1. **Whitelist file extensions**: Only allow known image formats (`jpg`, `jpeg`, `png`, `gif`). The `pathinfo()` function extracts the extension, converted to lowercase for case-insensitive comparison. If the extension is not in the whitelist, the upload is rejected with a 400 error.

2. **Generate a safe filename**: Instead of using the user-supplied filename directly, generate a random filename using `bin2hex(random_bytes(16))` and append only the validated extension. This prevents path traversal and name-based attacks, and ensures the server cannot execute the uploaded file regardless of its actual type.

These controls work together: the whitelist ensures only image extensions pass, and the generated filename ensures the server will serve the file as a static asset even if the client's metadata is misleading. For defense-in-depth, configure the server to never execute code in the uploads directory (e.g., disable PHP execution via `.htaccess` or web server configuration).
