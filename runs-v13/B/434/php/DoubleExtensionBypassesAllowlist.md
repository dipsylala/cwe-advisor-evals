## Verdict

**Confirmed**: CWE-434 Unrestricted Upload of File with Dangerous Type.

The vulnerable code uses filename-based extension checking via `strpos()`, which is bypassable with double extensions (e.g., `shell.php.jpg`). It stores uploaded files using the original client-supplied filename without validating actual file content, and does not check the return value of `move_uploaded_file()`.

## Source

**File**: `evals/cases/434/php/DoubleExtensionBypassesAllowlist/DoubleExtensionBypassesAllowlist.php`  
**Line**: 36 (sink: `move_uploaded_file()`)  
**Data flow**:
- Line 14: Source is `$_FILES['avatar']['name']` (client-supplied filename)
- Lines 18–25: Unsafe validation using `strpos()` checks if any allowed extension appears anywhere in the filename
- Line 33: Original filename used directly to construct destination path
- Line 36: File moved to destination without validating actual content

**Vulnerability**: Double-extension bypass (e.g., `invoice.php.jpg` passes the check because `.jpg` is found via `strpos()`, but the server executes the `.php` extension). No magic-byte validation. No server-generated filename to prevent traversal or extension choice by attacker.

## Fix

Replace the unsafe extension-based allowlist with content-based validation using `finfo_file()`, generate a server-side filename, and derive the stored extension from the detected MIME type:

```php
<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by validating actual content
 * and storing with a server-generated filename.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    // Verify fileinfo extension is available
    if (!extension_loaded('fileinfo')) {
        return ['ok' => false, 'error' => 'Server misconfiguration'];
    }

    // Map allowed MIME types to safe extensions
    $allowedMimeTypes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
    ];

    // Detect actual file type from content (magic bytes), not filename
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        return ['ok' => false, 'error' => 'Server error'];
    }
    
    $detectedMimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    // Validate detected type against allowlist
    if (!isset($allowedMimeTypes[$detectedMimeType])) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Get the safe extension from the allowlist, not from filename
    $safeExtension = $allowedMimeTypes[$detectedMimeType];

    // Generate server-side filename to prevent directory traversal and extension bypass
    $storedFilename = bin2hex(random_bytes(16)) . '.' . $safeExtension;
    $destination = $uploadDir . '/' . $storedFilename;

    // Move the validated file to storage
    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        return ['ok' => false, 'error' => 'Failed to save file'];
    }

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

The fix addresses CWE-434 by replacing the unsafe extension-based check with content-based validation:

1. **Fileinfo validation**: Uses `finfo_file(FILEINFO_MIME_TYPE)` to detect the actual MIME type from file magic bytes (content signature), not the filename. This prevents bypasses using mismatched extensions.

2. **Allowlist mapping**: Maintains a whitelist of permitted MIME types mapped to canonical safe extensions. The detected type is validated against this map; mismatches are rejected.

3. **Taint break**: After validation, the extension is derived from the allowlist-mapped safe value, not from `$_FILES['name']`. A fresh variable `$safeExtension` carries the canonical value downstream.

4. **Server-generated filename**: Uses `bin2hex(random_bytes(16))` to create a cryptographically random filename, preventing the attacker from controlling the extension or performing directory traversal (e.g., `../admin/shell`).

5. **Return-value check**: Adds verification that `move_uploaded_file()` succeeded before returning success, catching I/O failures.

6. **Extension availability check**: Validates that the Fileinfo extension is loaded at startup; if absent, the function does not exist at all and the check will error rather than silently fail.

## Behaviour changes

- **Filename**: Uploaded files are stored with a random server-generated name (e.g., `a3f5e2b1c8d9f4e7.jpg`) instead of the original client-supplied name. The original name is discarded; users cannot browse by recognizable filename in the uploads directory.
- **Validation**: Files are rejected if their content signature does not match an allowed image MIME type, even if the filename has an allowed extension (e.g., a text file renamed to `.jpg` is now rejected).
- **Error handling**: Returns a new error `'Failed to save file'` if `move_uploaded_file()` fails, in addition to the existing `'Upload failed'` and `'Unsupported file type'` responses.
- **Extension bypass**: Double-extension attacks (`shell.php.jpg`) no longer bypass the filter; the stored file receives only the extension matching its detected content type.
- **Configuration dependency**: Requires the Fileinfo extension (`ext-fileinfo` in PHP) to be installed and enabled. The function now fails if it is missing.
