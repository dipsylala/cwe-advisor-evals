## Verdict

**Confirmed.** The upload endpoint accepts files without validating their actual content, trusts the client-supplied filename for storage, and places the file in a web-accessible directory. An attacker can upload executable content (e.g., a PHP script with a spoofed `.jpg` extension) and either serve it back through a request to the upload path or exploit a separate path-traversal or double-extension vulnerability to execute it.

## Source

`$_FILES['avatar']` superglobal from the HTTP multipart form request.

## Fix

Replace the unsafe upload handler with one that validates file content, generates a server-side filename, and restricts execution in the upload directory:

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

    // Verify Fileinfo extension is available; fatal error if missing means the check will not silently fail.
    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'File validation unavailable.';
        return;
    }

    // Allowlist of permitted MIME types for avatar images.
    $allowedTypes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp',
    ];

    // Detect the real MIME type from file content (magic bytes).
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    // Validate the detected type against the allowlist.
    if (!isset($allowedTypes[$detectedType])) {
        http_response_code(400);
        echo 'File type not permitted.';
        return;
    }

    // Get the safe extension from the allowlist, not the client-supplied filename.
    $safeExtension = $allowedTypes[$detectedType];

    // Generate a server-side filename to prevent both direct execution and traversal attacks.
    $storedFilename = bin2hex(random_bytes(16)) . '.' . $safeExtension;
    $uploadDir = __DIR__ . '/uploads/avatars/';
    $destination = $uploadDir . $storedFilename;

    // Move the uploaded file to storage.
    if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
        http_response_code(500);
        echo 'Failed to store upload.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

### File: .htaccess

Add this file to the `uploads/avatars/` directory to disable PHP script execution:

```
# Disable script execution in this directory.
<FilesMatch "\.ph(p[0-9]?|tml)$">
    Require all denied
    SetHandler none
</FilesMatch>

# Prevent direct access to scripts for defense-in-depth.
AddType text/plain .php .phtml .php3 .php4 .php5 .php7 .phar
```

## Explanation

The original code trusts the client-supplied filename (`$_FILES['avatar']['name']`) for storage and never validates the file's actual content. An attacker can upload a PHP script renamed with an `.jpg` extension, bypass extension-based filtering, and either directly access it at the web-exposed URL or exploit the double-extension pattern (e.g., `shell.php.jpg`) if the server is misconfigured to run the last or an earlier extension.

The fix applies the core CWE-434 remediation:

1. **Content validation**: `finfo_file()` inspects the file's actual magic bytes and detects the real MIME type, preventing disguised executables.
2. **Allowlist enforcement**: Only MIME types in the `$allowedTypes` map are accepted; the extension is derived from this allowlist, not from the filename.
3. **Server-side filename generation**: `bin2hex(random_bytes(16))` generates a cryptographically random name unrelated to the client input, preventing both path traversal (`../../../etc/passwd`) and double-extension attacks.
4. **Execution hardening**: The `.htaccess` file disables PHP execution in the upload directory as a defense-in-depth measure, so even if a PHP file somehow arrives, it is served as text rather than executed.

## Behaviour changes

- **Upload rejection**: Files whose actual content does not match an allowlist entry are rejected with HTTP 400. Previously, any file with any extension would be accepted and stored.
- **Filename mutation**: Stored filenames are now random server-generated strings (e.g., `a1b2c3d4e5f6g7h8.jpg`) rather than the client-supplied name. Applications retrieving avatars must use a database record or index to map the original upload request to the stored filename, or serve files through a script that does the lookup server-side.
- **Directory hardening**: The `.htaccess` rules prevent PHP execution in the upload directory, closing a secondary execution vector if an attacker somehow bypasses the allowlist or if a legacy PHP version or misconfigured server runs scripts in that location.
- **Fileinfo dependency**: The fix requires the Fileinfo extension (`extension_loaded('fileinfo')`) and explicitly fails if it is not available, rather than silently skipping validation. This is intentional: a silent failure on a critical security check is worse than an error.
