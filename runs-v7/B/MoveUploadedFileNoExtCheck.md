## Verdict

Exploitable. The code accepts uploaded files and stores them without validating the file type, allowing an attacker to upload and store an executable script (e.g., a PHP file) that could be served or executed.

## Source

`$_FILES['avatar']['name']` (line 13) and `$_FILES['avatar']['tmp_name']` (line 17) - client-supplied filename and temporary upload file from the multipart request.

## Fix

**Vulnerable code:**
```php
    $uploadDir = __DIR__ . '/uploads/avatars/';
    $originalName = $_FILES['avatar']['name'];
    $destination = $uploadDir . $originalName;

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

**Fixed code:**
```php
    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'File upload not available.';
        return;
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    // Allowlist permitted image MIME types
    $allowedMimes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
    ];

    if (!isset($allowedMimes[$mimeType])) {
        http_response_code(400);
        echo 'Invalid file type.';
        return;
    }

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $extension = $allowedMimes[$mimeType];
    $destination = $uploadDir . bin2hex(random_bytes(16)) . '.' . $extension;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

## Explanation

The fix validates the uploaded file's actual content using the Fileinfo extension (`finfo_file()`) rather than trusting the client-supplied filename extension. The detected MIME type is checked against an allowlist of permitted image formats. Only after validation passes is a server-generated filename created using `bin2hex(random_bytes(16))`, with the extension derived from the allowlist map rather than from user input. This prevents an attacker from uploading an executable script by forging a filename extension or Content-Type header - the real file content is inspected and rejected if it doesn't match an allowed image type.

## Behaviour changes

- **Added fileinfo check**: Verifies the Fileinfo extension is loaded before processing uploads. If absent, returns a 500 error with a descriptive message. Reason: Fileinfo is required for safe type detection; a missing extension should fail fast rather than silently skip validation.
- **Added file-type validation**: Reads the actual MIME type from the uploaded file and rejects uploads that don't match an allowlist. Returns 400 with an error message on mismatch. Reason: This is the core defence against dangerous file types.
- **Added server-generated filename**: Replaces `$originalName` with a random hex string, derived from `bin2hex(random_bytes(16))`. Reason: Prevents path traversal and ensures attackers cannot control the stored filename or its extension.
- **Extension now derives from detected type**: The file extension is taken from the `$allowedMimes` map, not from the client-supplied name. Reason: Prevents double extensions and ensures the extension matches the actual file content.
