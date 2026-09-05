## Verdict

exploitable

## Source

`$_FILES['avatar']['name']` (client-supplied filename) and `$_FILES['avatar']['tmp_name']` (uploaded file content)

## Fix

**Vulnerable code:**
```php
$uploadDir = __DIR__ . '/uploads/avatars/';
$originalName = $_FILES['avatar']['name'];
$destination = $uploadDir . $originalName;

move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

**Fixed code:**
```php
// Validate that fileinfo extension is available
if (!extension_loaded('fileinfo')) {
    http_response_code(500);
    echo 'Upload configuration error.';
    return;
}

// Detect actual MIME type from file content, not client-supplied name or type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$detectedType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
finfo_close($finfo);

// Allowlist permitted MIME types and their safe extensions
$allowedTypes = [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/gif' => 'gif',
    'image/webp' => 'webp',
];

// Reject if detected type is not in allowlist
if (!isset($allowedTypes[$detectedType])) {
    http_response_code(400);
    echo 'Unsupported file type.';
    return;
}

// Generate server-side filename using the allowlist-validated extension
$uploadDir = __DIR__ . '/uploads/avatars/';
$extension = $allowedTypes[$detectedType];
$filename = bin2hex(random_bytes(16)) . '.' . $extension;
$destination = $uploadDir . $filename;

move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

## Explanation

The original code constructs the upload destination path directly from `$_FILES['avatar']['name']`, which is client-controlled and can contain executable extensions like `.php`. This allows an attacker to upload a PHP web shell and have it executed by the server. The fix validates the actual file content using `finfo_file()` to detect the real MIME type (not the client-supplied `Content-Type` header or filename extension), checks it against an allowlist of permitted types, and stores the file under a server-generated random name with an extension derived from the detected type. This prevents an attacker from specifying an executable extension regardless of the actual file content, and eliminates the ability to choose the storage filename or path. The fix assumes the upload directory is configured to prevent script execution (via `.htaccess` or web server configuration) as a secondary control.

## Behaviour changes

**Filename changes:** The stored filename is now server-generated (`bin2hex(random_bytes(16))` + safe extension) instead of using the client-supplied `$_FILES['avatar']['name']`. This is necessary to close the weakness and does not affect the application's ability to serve files — the application now manages the filename mapping server-side.

**Type validation:** The code now performs MIME type detection and validation before accepting the file. Files with disallowed types are rejected with a 400 response instead of being stored. This is the core fix and changes behaviour intentionally to reject dangerous uploads.

**Configuration check:** The code verifies that the `fileinfo` extension is loaded and returns a 500 error if it is missing, preventing silent failure of the validation. This is a necessary safety check that makes the validation failure visible rather than allowing unvalidated uploads to proceed.

**No other behaviour changes:** The `move_uploaded_file()` call signature remains identical, and successful uploads still write to the same `$uploadDir` directory. Error responses and success message remain the same.
