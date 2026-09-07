## Verdict

REAL. The code uses `strpos()` to check if an allowed extension appears anywhere in the client-supplied filename. This allows a double-extension bypass: an attacker uploads `shell.php.jpg`, which passes validation because `.jpg` is found in the string, but PHP executes the `.php` extension when configured to run scripts. The file is stored under the original name with the attacker-controlled extension chain intact. The core failures are: (1) substring matching instead of validating the final extension, (2) no inspection of actual file content, and (3) storage under the original client filename.

## Source

The vulnerability spans lines 14–36:
- Line 14: `$originalName = $file['name']` reads the untrusted filename
- Lines 20–24: Validation using `strpos()` checks if an allowed extension exists anywhere in the string, not at the end
- Line 33: `$destination = $uploadDir . '/' . $originalName` builds the storage path from the untrusted name
- Line 36: `move_uploaded_file($file['tmp_name'], $destination)` executes the move to the attacker-controlled path

Data flows from client-supplied `$_FILES['avatar']['name']` through the weak substring check to the storage sink, allowing a file named `shell.php.jpg` to bypass the allowlist and be written to disk with both extensions intact.

## Fix

```php
<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by validating actual file content,
 * generating a server-side filename, and storing outside script execution.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    // Verify fileinfo extension is available; fatal error if not.
    if (!extension_loaded('fileinfo')) {
        return ['ok' => false, 'error' => 'Fileinfo extension not available'];
    }

    // Map of allowed MIME types to safe extensions (server-controlled).
    $mimeToExt = [
        'image/jpeg' => '.jpg',
        'image/png'  => '.png',
        'image/gif'  => '.gif',
    ];

    // Detect the actual MIME type from file content, not filename.
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    // Reject if the detected MIME type is not in the allowlist.
    if (!isset($mimeToExt[$mimeType])) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Generate a server-side filename using the detected type's extension.
    $safeFilename = bin2hex(random_bytes(16)) . $mimeToExt[$mimeType];
    $destination = $uploadDir . '/' . $safeFilename;

    // FIXED: move_uploaded_file() now receives a generated filename and an allowlist-matched extension.
    move_uploaded_file($file['tmp_name'], $destination);

    return ['ok' => true, 'path' => $destination];
}

$result = handleAvatarUpload($_FILES['avatar'], __DIR__ . '/uploads');
if (!$result['ok']) {
    http_response_code(400);
    echo json_encode(['error' => $result['error']]);
    exit;
}

echo json_encode(['path' => $result['path']]);
```

## Explanation

The fix eliminates the weakness by replacing substring-based extension validation with actual content inspection and server-controlled naming:

1. **Remove substring check**: The original `strpos()` loop that looked for allowed extensions anywhere in the filename is replaced with `finfo_file()`, which inspects the file's actual bytes (magic signature) to determine its real type.

2. **Validate against MIME allowlist**: The detected MIME type is checked against a server-controlled `$mimeToExt` map, which enforces both that the type is allowed and provides the canonical safe extension for that type (breaking taint—the original filename is never used downstream).

3. **Generate server-side filename**: Instead of using `$file['name']`, a random 16-byte hex string is generated with `bin2hex(random_bytes(16))`, making the filename unpredictable and preventing extension-chain attacks.

4. **Extension from detected type**: The stored extension comes from the allowlist map entry, not the client-supplied filename, so a file with real content `image/jpeg` will always be stored as `.jpg` regardless of what the client named it.

5. **Assumption**: Code assumes the upload directory (`uploadDir`) is configured to prevent script execution (e.g., `.htaccess` with `php_flag engine off` under mod_php, or a handler-deny rule under FPM; or that it is outside the document root and accessed only through a delivery script). This is a defence-in-depth control documented in the CWE-434 guidance.

The fix preserves the sink's contract: `move_uploaded_file()` still receives a path string and moves the temporary file there, and the function still returns the stored path to the caller. The difference is that the path and extension are now server-controlled, not attacker-controlled.

## Behaviour changes

- **Input acceptance**: Files are now accepted or rejected based on detected MIME type (magic bytes), not filename extension. A file with `.jpg` extension but PNG content will be rejected; a file with `.php` extension but `image/jpeg` content will be accepted and stored as `.jpg`.
- **Stored filename**: The file is stored with a random 16-character hex name (e.g., `a3f7c2e91b4d6e8a.jpg`) instead of the original filename. This path is returned to the caller and should be stored for later reference if the application needs to serve the file back.
- **Extension determinism**: The stored extension is always determined by the detected MIME type, never by the client's original filename. Double extensions and path-traversal sequences in the original name are eliminated because they do not appear in the stored path.
