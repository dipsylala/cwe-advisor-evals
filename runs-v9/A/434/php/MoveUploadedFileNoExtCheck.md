## Verdict

Confirmed. The handler moves an uploaded file to a web-accessible directory using the attacker-supplied original filename, with no validation of file type, extension, or content. An attacker can upload a file such as `shell.php` and, if the web server executes PHP from `uploads/avatars/`, achieve remote code execution.

## Source

`$_FILES['avatar']['name']` (line 13) — the client-supplied original filename, fully attacker-controlled and untrusted. It flows unmodified into `$destination` (line 14) and is used as the target path for `move_uploaded_file()` at the sink on line 17. No extension allowlist, no MIME/content check, and no filename sanitization occurs anywhere in between.

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

    // Enforce a size limit defensively even though php.ini also bounds this.
    $maxBytes = 5 * 1024 * 1024;
    if ($_FILES['avatar']['size'] > $maxBytes) {
        http_response_code(400);
        echo 'File too large.';
        return;
    }

    // Determine the real content type from the file's contents, not the
    // client-supplied name or Content-Type header.
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($tmpName);

    $allowedTypes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];

    if (!isset($allowedTypes[$mimeType])) {
        http_response_code(400);
        echo 'Unsupported file type.';
        return;
    }

    // Confirm it is actually a valid, decodable image (rejects polyglot
    // files that pass the MIME sniff but aren't real images).
    if (@getimagesize($tmpName) === false) {
        http_response_code(400);
        echo 'Invalid image file.';
        return;
    }

    $uploadDir = __DIR__ . '/uploads/avatars/';

    // Never reuse the client-supplied name: generate a random filename with
    // an extension derived from the verified MIME type, not from user input.
    $extension = $allowedTypes[$mimeType];
    $safeName = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . $safeName;

    if (!move_uploaded_file($tmpName, $destination)) {
        http_response_code(500);
        echo 'Upload failed.';
        return;
    }

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The original code has two compounding weaknesses. First, it derives the destination filename directly from `$_FILES['avatar']['name']`, which is fully attacker-controlled — nothing stops a request from naming the file `shell.php`, `shell.phtml`, or any other server-executable extension. Second, it performs no check on the file's actual content, so even an extension allowlist alone would not stop a polyglot upload (e.g., a valid GIF header followed by PHP code) from later being reinterpreted as code if the server's extension-to-handler mapping is ever misconfigured.

The fix addresses both angles:

- **Content-based type verification**: `finfo::file()` inspects the file's magic bytes to determine its real MIME type, and `getimagesize()` further confirms the file parses as a genuine image — together these are far harder to spoof than trusting the client-sent filename or `Content-Type` header.
- **Allowlist, not denylist**: only a fixed set of known-safe image MIME types is accepted, and the stored extension is derived from that verified type rather than echoed from user input, so a `.php`-named upload can never reach disk with an executable extension.
- **Randomized filename**: discarding the original name entirely also eliminates path-traversal and overwrite risks from filenames containing `../` or targeting an existing file, and removes any possibility of double-extension tricks (`avatar.jpg.php`).
- **Size cap**: bounds resource consumption independent of `php.ini` settings, which may not be enforced consistently across environments.

Defense in depth beyond this function: the web server should also be configured to never execute scripts from the `uploads/avatars/` directory (e.g., via a directory-scoped handler/MIME override, or by serving uploads from a path outside the document root through a dedicated read-only script), so that even a misclassified file cannot run as code. That server/deployment configuration is outside this function's scope but should be verified alongside this code fix.
