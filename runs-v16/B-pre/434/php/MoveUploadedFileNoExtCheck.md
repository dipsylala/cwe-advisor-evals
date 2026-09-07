## Verdict

Exploitable. The application accepts uploaded files without validating their type or content. An attacker can upload a PHP script or other executable file to a web-accessible directory, leading to Remote Code Execution.

## Source

`$_FILES['avatar']['name']` (line 13) and `$_FILES['avatar']['tmp_name']` (line 17) - the uploaded filename and temporary file content are attacker-controlled and taken from the HTTP request without validation. The destination path is constructed directly from the untrusted filename and never checked against an allowlist of permitted types.

## Fix

**Vulnerable code:**
```php
$originalName = $_FILES['avatar']['name'];
$destination = $uploadDir . $originalName;

// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

**Fixed code:**
```php
// Verify Fileinfo extension is loaded
if (!extension_loaded('fileinfo')) {
    http_response_code(500);
    echo 'Server configuration error.';
    return;
}

// Detect real MIME type from file content
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mimeType = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
finfo_close($finfo);

// Allowlist of permitted image types
$allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

// Map MIME types to file extensions
$mimeToExt = [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/gif' => 'gif',
    'image/webp' => 'webp'
];

// Validate against allowlist
if (!in_array($mimeType, $allowedMimes, true)) {
    http_response_code(400);
    echo 'Invalid file type.';
    return;
}

// Generate server-side filename
$extension = $mimeToExt[$mimeType];
$filename = bin2hex(random_bytes(16)) . '.' . $extension;
$destination = $uploadDir . $filename;

// Move the file to the destination
if (!move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)) {
    http_response_code(500);
    echo 'Failed to save upload.';
    return;
}
```

## Explanation

The fix introduces three critical changes: (1) it validates the uploaded file's real content type using `finfo_file()`, which inspects the file's magic bytes rather than trusting the client-supplied Content-Type header or filename extension; (2) it checks the detected MIME type against an allowlist of permitted image formats and rejects any file that does not match, terminating early to prevent further processing; (3) it generates a server-controlled filename using `bin2hex(random_bytes(16))` instead of using the original filename, and derives the file extension from the validated MIME type through a fixed mapping table. Together, these changes ensure only legitimate image files can be uploaded, and they are stored under a randomized name that the attacker cannot predict or exploit for code execution.

## Behaviour changes

**Early validation failures:** The fixed code now returns HTTP 500 if the Fileinfo extension is not available, and HTTP 400 if the file type does not match an allowed type. The original code would have accepted any file and stored it regardless of its actual content, so these new rejection paths prevent upload of dangerous file types. The change is necessary to enforce the allowlist gate.

**Enhanced error handling:** The fixed code wraps the `move_uploaded_file()` call in a check for its return value and returns HTTP 500 if the move fails. The original code did not validate the function's success, so a silent failure would have left the file in the temporary directory and reported success to the client. The new validation is defensive and does not alter the successful-path behavior.

**Filename generation:** The stored filename is now server-generated (`bin2hex(random_bytes(16)) . '.' . $extension`) instead of client-supplied. This prevents the attacker from controlling the filename and its extension. The change is required to eliminate the weakness.
