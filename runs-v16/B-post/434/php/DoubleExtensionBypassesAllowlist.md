## Verdict

**Confirmed.** The code at line 36 is vulnerable to CWE-434 (Unrestricted Upload of File with Dangerous Type). The double-extension bypass is present and exploitable:

1. The filename allowlist check uses `strpos()` which matches allowed extensions anywhere in the filename (e.g., `malicious.php.jpg` passes)
2. No validation of the actual file content via magic bytes or MIME type detection
3. The original client-supplied filename is used directly as the storage path, preserving the extension chain

An attacker can upload `shell.php.jpg`, which passes the extension check but executes as PHP on servers configured to execute based on any extension in the chain or with a misconfigured MIME handler.

## Source

- **Entry point**: `$_FILES['avatar']` superglobal (lines 14-15)
- **Weak validation**: Lines 20-25 check if any allowed extension substring appears in `$originalName`, using `strpos()`
- **Unsafe sink**: Line 36 passes the original `$_FILES['x']['name']` via `$destination` to `move_uploaded_file()`

## Fix

```php
<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by validating actual file content
 * (magic bytes/MIME type) and storing under a generated name outside execution scope.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    // Verify fileinfo extension is available
    if (!extension_loaded('fileinfo')) {
        return ['ok' => false, 'error' => 'System misconfiguration'];
    }

    // Map MIME types to safe extensions; allowlist only these types
    $mimeToExtension = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
    ];

    // Detect real MIME type from file content (magic bytes), not the filename
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    if ($detectedMime === false) {
        return ['ok' => false, 'error' => 'Unable to verify file type'];
    }

    // Check if MIME type is in the allowlist
    if (!isset($mimeToExtension[$detectedMime])) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Generate a server-side filename from the validated type
    $extension = $mimeToExtension[$detectedMime];
    $storedName = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . '/' . $storedName;

    // Move file using the server-generated name, not the client-supplied one
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

The fix closes CWE-434 by replacing filename-based validation with content-based validation and server-generated storage paths:

1. **Content validation** (line 34): `finfo_file()` inspects the actual file content (magic bytes) and returns the real MIME type, independent of the filename extension or client-supplied `Content-Type` header.

2. **Allowlist enforcement** (lines 38-41): The detected MIME type is checked against a hardcoded allowlist of safe types. Only JPEG, PNG, and GIF are permitted; any other content type is rejected immediately.

3. **Canonical value selection** (lines 43-45): After validation, the extension is derived from the allowlist map (`$mimeToExtension`), not from the client's filename. This breaks the taint chain—the original `$_FILES['x']['name']` is never used after the allowlist check.

4. **Server-generated filename** (line 46): A random, cryptographically secure name is generated using `bin2hex(random_bytes(16))`, ensuring:
   - No extension chains or double-extension attacks (e.g., `shell.php.jpg`)
   - The attacker cannot influence the storage name
   - All stored files have a single, safe extension derived from their validated MIME type

5. **Extension consistency** (line 46): The stored filename carries only the extension matched to the validated MIME type, eliminating the double-extension bypass vector entirely.

The fix also adds a guard for the fileinfo extension (line 15–17) to fail safely if the system is misconfigured—a missing extension would cause `finfo_file()` to raise a fatal error, and an omitted check hides that failure.

**Sink contract preserved**: `move_uploaded_file()` still receives a valid file path and moves the temporary file to the destination; the function's return value and error semantics are unchanged. The only behavioural change is the destination filename—it is now server-controlled rather than attacker-controlled.

## Behaviour changes

- **Filename generation**: Uploaded files are stored as random hex names (e.g., `a3f2c8e1d9b4a7f2e5c1d8b3a9f6e2c4.png`) instead of the original client-supplied name. Any code displaying the stored file path to users will show the generated name, not the original upload name. To preserve a user-facing "original name" for display purposes, store the original name in a separate database column, never in the filesystem path.

- **MIME type detection**: Files are now validated by content inspection. Files with incorrect extensions (e.g., a real PNG file with a `.jpg` extension) will now be accepted based on their actual content and stored with the correct extension (`.png`). This is the intended behaviour and closes the bypass.

- **Hardcoded allowlist**: Only JPEG, PNG, and GIF are accepted. If other image formats must be supported in the future (e.g., WebP, SVG), they must be explicitly added to `$mimeToExtension` after confirming they are safe for your application's use case (e.g., SVG carries script and requires additional controls).
