## Verdict

Exploitable. `handleAvatarUpload()` accepts the client-supplied original filename and passes an unvalidated upload straight to `move_uploaded_file()` with no check on the file's real content, type, or extension. An attacker can submit a file named e.g. `shell.php` and have it written into `uploads/avatars/` under that same name; if that directory sits inside the document root and script execution is enabled there, the upload gives remote code execution.

## Source

`$_FILES['avatar']['name']` (client-controlled multipart filename) and `$_FILES['avatar']['tmp_name']` (the uploaded temp file's content, also entirely attacker-supplied) - both flow unchecked into `$destination` and then into `move_uploaded_file()` at line 17.

## Fix

Vulnerable code:

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

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $originalName = $_FILES['avatar']['name'];
    $destination = $uploadDir . $originalName;

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

Fixed code:

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

    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'Upload failed.';
        return;
    }

    // Allowlist of accepted avatar image types, mapping detected MIME type
    // to the extension used for storage. The extension is derived from this
    // map, never from the client-supplied filename.
    $allowedMimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMime = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
    finfo_close($finfo);

    if ($detectedMime === false || !isset($allowedMimeToExt[$detectedMime])) {
        http_response_code(400);
        echo 'Unsupported file type.';
        return;
    }

    $extension = $allowedMimeToExt[$detectedMime];
    $uploadDir = __DIR__ . '/uploads/avatars/';
    $storedName = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . $storedName;

    move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The fix replaces trust in the client-supplied filename with content-based validation and a server-generated storage name, per the PHP CWE-434 guidance. `finfo_file()` inspects the actual bytes of the uploaded temp file and returns its real MIME type, which is checked against a fixed allowlist of image types (`image/jpeg`, `image/png`, `image/gif`, `image/webp`); anything else - including a PHP script, an HTML/SVG file with embedded script, or a double-extension payload like `shell.php.jpg` - is rejected before it reaches `move_uploaded_file()`. The stored filename and its extension are both derived server-side (`bin2hex(random_bytes(16))` plus the extension taken from the allowlist map for the detected MIME type), so the attacker no longer controls either the name or the extension the file is ultimately stored and later served under. An `extension_loaded('fileinfo')` guard is added first because if the Fileinfo extension is missing, `finfo_open()`/`finfo_file()` do not exist and the failure would otherwise surface as a fatal error rather than a validation result, making the check look present when it silently isn't. `move_uploaded_file()` itself is unchanged as the sink; only what reaches it is now validated and renamed. Storing outside the document root and disabling script execution in the upload directory are additional hardening steps from the guidance that this fix does not apply, since they depend on the deployment's web server configuration and how the avatar is later served back, which are outside this file's visibility - this residual risk should be closed separately.

## Behaviour changes

- Added a new failure path returning HTTP 500 when the Fileinfo extension is unavailable. The original had no equivalent check and would instead have failed later with a fatal error under the same condition; this makes that failure mode explicit and controlled, per the PHP guidance's `extension_loaded('fileinfo')` recommendation.
- Added a new failure path returning HTTP 400 when the uploaded file's detected content type is not in the image allowlist. The original performed no such check and always attempted the move; this is the core fix for the finding.
- The stored filename changed from the client-supplied `$_FILES['avatar']['name']` to a randomly generated name (`bin2hex(random_bytes(16))`) with an extension taken from the MIME-to-extension allowlist, not from the original filename. This is required by the fix: it removes attacker control over both the stored name and extension, closing the path traversal and dangerous-extension avenues the original code left open.
- The storage directory (`uploads/avatars/`, under `__DIR__`) is unchanged. The guidance recommends storing outside the document root, but that change was not applied here because it would alter how avatars are served back to clients, and the serving code is not visible in this file - flagged above as a residual item rather than made silently.
- `move_uploaded_file()`'s return value is still discarded in both versions, and the success message is still echoed unconditionally on that path in both versions - no change to that part of the sink's contract.
