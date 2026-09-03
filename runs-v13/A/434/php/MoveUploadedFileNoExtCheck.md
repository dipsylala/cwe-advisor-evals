## Verdict
Valid. The code accepts file uploads without validating the file type or extension, allowing an attacker to upload executable code.

## Source
Line 13–14: The original filename from `$_FILES['avatar']['name']` is used directly as the destination without any validation. The attacker controls both the filename and its extension. Line 17: `move_uploaded_file()` stores the file at the untrusted destination with no type checking.

## Fix
Validate the file extension against a whitelist of permitted image types before moving the uploaded file:

```php
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
        echo 'Invalid file type. Only JPG, PNG, and GIF are allowed.';
        return;
    }

    // Generate a safe filename to prevent collisions and directory traversal
    $safeFileName = bin2hex(random_bytes(16)) . '.' . $fileExtension;
    $destination = $uploadDir . $safeFileName;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation
Without extension validation, an attacker can upload a file with a dangerous extension like `.php`, `.phtml`, or `.sh`. The web server will execute this file as code, leading to remote code execution. The fix enforces a whitelist of safe image extensions (`jpg`, `jpeg`, `png`, `gif`) and rejects any upload that does not match. Additionally, the filename is regenerated using random bytes to prevent collisions and make the file harder to target. The web server should also be configured to prevent execution of scripts within the upload directory (via `.htaccess` or web server configuration).
