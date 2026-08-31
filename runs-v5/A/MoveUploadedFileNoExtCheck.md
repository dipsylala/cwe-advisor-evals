## Verdict
Confirmed. `handleAvatarUpload()` takes the client-supplied `$_FILES['avatar']['name']`, concatenates it directly onto the upload directory, and passes the result straight to `move_uploaded_file()` with no check on file type, extension, or MIME content. An attacker can upload `shell.php` (or `.phtml`, `.php5`, etc.) into a directory that sits under the web root, then request it directly to get server-side code execution.

## Source
`$_FILES['avatar']['name']` (line 13) - the original filename submitted by the client in the multipart form upload. This value is fully attacker-controlled, including its extension and any path segments it contains.

## Fix
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

    $tmpName = $_FILES['avatar']['tmp_name'];

    // Determine the real file type from content, not the client-supplied name/MIME header.
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $detectedType = $finfo->file($tmpName);

    $allowedTypes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];

    if (!isset($allowedTypes[$detectedType])) {
        http_response_code(400);
        echo 'Unsupported file type.';
        return;
    }

    // Re-encode through GD to strip any polyglot payload embedded in the image data.
    $image = match ($detectedType) {
        'image/jpeg' => imagecreatefromjpeg($tmpName),
        'image/png'  => imagecreatefrompng($tmpName),
        'image/gif'  => imagecreatefromgif($tmpName),
        'image/webp' => imagecreatefromwebp($tmpName),
        default      => false,
    };

    if ($image === false) {
        http_response_code(400);
        echo 'Invalid image file.';
        return;
    }

    $uploadDir = __DIR__ . '/uploads/avatars/';

    // Generate the filename server-side; never derive it from client input.
    $extension = $allowedTypes[$detectedType];
    $destination = $uploadDir . bin2hex(random_bytes(16)) . '.' . $extension;

    $saved = match ($extension) {
        'jpg'  => imagejpeg($image, $destination, 85),
        'png'  => imagepng($image, $destination),
        'gif'  => imagegif($image, $destination),
        'webp' => imagewebp($image, $destination),
    };
    imagedestroy($image);

    if (!$saved) {
        http_response_code(500);
        echo 'Failed to save avatar.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation
The original code trusted the client-supplied filename for both the destination path and (implicitly) the file's type, and never inspected the uploaded content. That lets an attacker submit a file named `shell.php` with a `.php` extension; `move_uploaded_file()` writes it verbatim into `uploads/avatars/`, and if that directory is reachable over HTTP, requesting the file executes it as PHP on the server - a classic unrestricted-upload-to-RCE chain. A client-side or `Content-Type` header check would not have helped either, since both are attacker-controlled and easy to spoof.

The fix removes every place where the original filename or its extension influences the outcome:

- **Type is verified from content, not the name.** `finfo::file()` with `FILEINFO_MIME_TYPE` inspects the actual bytes of the temporary upload (`tmp_name`) rather than trusting the `name` or `type` fields from `$_FILES`, both of which the client fully controls.
- **Only a small allowlist of image types is accepted.** Anything not in `$allowedTypes` (including `.php`, `.phtml`, `.svg`, `.htaccess`, etc.) is rejected outright, so no executable or config file can reach the upload directory regardless of what name it was submitted under.
- **The file is re-encoded through GD** (`imagecreatefromjpeg`/`imagepng`/etc.) rather than copied byte-for-byte. This defeats polyglot files that are valid images but also carry embedded PHP or HTML/JS payloads (a common bypass for extension/MIME-only checks), since re-encoding rewrites the pixel data into a fresh file that no longer contains the original bytes.
- **The stored filename is generated server-side** with `random_bytes()` and a fixed, allowlisted extension, eliminating both the code-execution risk from a malicious extension and path traversal via `../` sequences that could otherwise be smuggled in through the original name.
- **Errors are handled explicitly at each stage** (unsupported type, invalid image, failed save) rather than silently proceeding, so a rejected upload never reaches `move_uploaded_file()`'s replacement (`imagejpeg`/`imagepng`/etc. in this version).

If avatars do not strictly need to be raster images (e.g. SVG must be supported), the content-inspection and re-encode step must be replaced with a dedicated sanitizer for that format, since SVG can carry embedded script content that image re-encoding does not address.
