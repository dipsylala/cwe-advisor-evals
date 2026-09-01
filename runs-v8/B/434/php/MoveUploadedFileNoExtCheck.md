## Verdict

CWE-434 is confirmed. The code does not validate the uploaded file's type or content, uses the client-supplied filename directly for storage, and stores within the application directory. An attacker can upload a PHP script with a spoofed extension or MIME type, execute it on the server, and compromise the application.

## Source

The vulnerability is in the upload handler at line 17. The data flow is:
- `$_FILES['avatar']['name']` (client-supplied, untrusted) is assigned to `$originalName` (line 13)
- `$originalName` is concatenated into the storage path `$destination` (line 14)
- `$destination` is passed to `move_uploaded_file()` (line 17) with no prior validation of file type, content, or extension

The upload directory path suggests storage within the application's webroot, where PHP execution is likely enabled by default.

## Fix

```php
<?php
// Handles avatar image uploads for a user profile form.

function handleAvatarUpload(): void
{
    // Verify the extension check is available
    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'Upload configuration error.';
        return;
    }

    if (!isset($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    // Allowlist of safe MIME types for avatar images
    $allowedMimes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
        'image/gif'  => 'gif',
    ];

    // Verify the actual file content type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMime = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    if (!isset($allowedMimes[$detectedMime])) {
        http_response_code(400);
        echo 'Invalid file type.';
        return;
    }

    // Enforce file size limit (5 MB)
    $maxSize = 5 * 1024 * 1024;
    if ($_FILES['avatar']['size'] > $maxSize) {
        http_response_code(400);
        echo 'File too large.';
        return;
    }

    $uploadDir = __DIR__ . '/uploads/avatars/';
    
    // Generate a server-side filename with the extension derived from detected type
    $storedFilename = bin2hex(random_bytes(16)) . '.' . $allowedMimes[$detectedMime];
    $destination = $uploadDir . $storedFilename;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix applies three key protections from the CWE-434 PHP guidance:

1. **Validate actual content type** - Uses `finfo_file(FILEINFO_MIME_TYPE)` to inspect the file's magic bytes rather than trusting the client-supplied `$_FILES['avatar']['type']` header. The allowlist `$allowedMimes` defines the only acceptable MIME types for avatar images.

2. **Generate a server-side filename** - Replaces the client-supplied `$_FILES['avatar']['name']` with a server-generated name using `bin2hex(random_bytes(16))`. This prevents an attacker from controlling the filename or extension, closing the path to extension-based execution (e.g., `shell.php.jpg` → `.jpg` extension chosen by attacker → double extension executed).

3. **Map detected type to safe extension** - The extension written to storage comes only from the `$allowedMimes` allowlist, derived from the detected MIME type. The original filename's extension is discarded.

4. **Add file size validation** - Enforces a 5 MB limit as secondary hardening against resource exhaustion.

5. **Verify fileinfo extension availability** - Checks that the Fileinfo extension is loaded before calling `finfo_file()`, preventing silent bypass if the extension is missing.

The fix breaks the taint chain by ensuring that the attacker's control ends at upload detection, not at storage path construction. The stored filename and extension are determined entirely by server logic and the verified file content, not by client input.

## Behaviour changes

**Before fix:**
- Any file was accepted and stored with its original client-supplied name in the upload directory
- An attacker could upload a PHP script as `shell.jpg` or with `Content-Type: image/jpeg`, store it in an executable directory, and execute it via direct web access

**After fix:**
- Only image files matching the allowlist MIME types (JPEG, PNG, WebP, GIF) are accepted
- All other files are rejected with a 400 response and "Invalid file type" message
- Accepted files are stored with a server-generated filename (e.g., `a3f2e1b9c4d7f2e1.jpg`) and safe extension
- The original filename is completely discarded; filename-based attacks are impossible
- Files exceeding 5 MB are rejected with a 400 response and "File too large" message
- If Fileinfo extension is unavailable, uploads fail with a 500 response and "Upload configuration error" message, preventing silent bypass

The fix preserves the successful upload response ("Avatar uploaded successfully.") for valid files and maintains HTTP error codes for different failure scenarios.
