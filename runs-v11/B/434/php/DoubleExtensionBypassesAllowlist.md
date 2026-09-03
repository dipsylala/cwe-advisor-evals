## Verdict
exploitable

## Source
`$_FILES['avatar']['name']` (client-supplied filename from multipart upload)

## Fix

**Vulnerable code (lines 18-36):**
```php
    // Only allow filenames that contain one of the approved image
    // extensions somewhere in the name.
    $allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'];
    $hasAllowedExtension = false;
    foreach ($allowedExtensions as $ext) {
        if (strpos(strtolower($originalName), $ext) !== false) {
            $hasAllowedExtension = true;
            break;
        }
    }

    if (!$hasAllowedExtension) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Keep the client's original filename (extension chain and all) so
    // the avatar keeps a recognizable name in the uploads listing.
    $destination = $uploadDir . '/' . $originalName;

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    move_uploaded_file($file['tmp_name'], $destination);
```

**Fixed code:**
```php
    // Map MIME types to their safe stored extensions
    $mimeToExt = [
        'image/jpeg' => '.jpg',
        'image/png'  => '.png',
        'image/gif'  => '.gif',
    ];

    // Detect actual file type from bytes, not from filename
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        return ['ok' => false, 'error' => 'File validation unavailable'];
    }

    $detectedMimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    if ($detectedMimeType === false || !isset($mimeToExt[$detectedMimeType])) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Generate server-side filename with extension derived from detected type
    $storedFilename = bin2hex(random_bytes(16)) . $mimeToExt[$detectedMimeType];
    $destination = $uploadDir . '/' . $storedFilename;

    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        return ['ok' => false, 'error' => 'Failed to store upload'];
    }
```

## Explanation

The original code uses substring matching (`strpos()`) on the filename to validate file type, allowing a double-extension bypass—a file named `shell.php.jpg` passes the check because it contains `.jpg`, but the server executes it as `.php`. The fix detects the actual file content type using `finfo_file()`, which reads magic bytes from the file itself (immune to filename spoofing), and compares it against an allowlist. The storage path is generated server-side using `bin2hex(random_bytes(16))`, which prevents the attacker from controlling the final extension. The stored extension is taken only from the MIME-type-to-extension map, breaking the taint between the client-supplied filename and the stored extension.

## Behaviour changes

- **Returned path**: Changed from the client's original filename to a server-generated random name. This is necessary because the original filename is untrusted and using it as the storage path is part of the vulnerability. Callers expecting the original name in the response will need to be aware the uploaded file is stored under a different path; this is the secure pattern.
- **MIME type check strictness**: Changed from substring search on the filename to magic-byte detection. The original check was based on filename suffixes alone; the fixed check verifies actual content against the allowlist. Files with forged extensions but mismatched content are now rejected.
- **Return value handling**: Added explicit check of `move_uploaded_file()`'s boolean return value and error reporting. The original code ignored it, which silently failed if the move operation failed; the fix surfaces the error.
- **Fileinfo availability**: The fix requires the Fileinfo extension (`finfo_file()` function). If it is not loaded, the function returns an error. This is a hard requirement—the original code had no check for this availability.
