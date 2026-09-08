## Verdict

Confirmed. The handler builds the destination path directly from the client-supplied `$_FILES['avatar']['name']` and passes it to `move_uploaded_file()` with no extension allowlist and no validation that the uploaded content is actually an image. An attacker can upload `shell.php` (or `shell.phtml`/`.php5`, etc.) and, since it lands under a path served by the web root (`uploads/avatars/`), request it directly to get arbitrary PHP execution on the server.

## Source

`$_FILES['avatar']['name']` (attacker-controlled, taken verbatim as `$originalName`) flows unchanged into `$destination = $uploadDir . $originalName;`, which is then used as the target path of `move_uploaded_file($_FILES['avatar']['tmp_name'], $destination)` on line 17 — the reported sink. Nothing between the source and the sink inspects the extension or the file's actual content type.

## Fix

### File: MoveUploadedFileNoExtCheck.php

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
    $tmpName = $_FILES['avatar']['tmp_name'];

    // Allowlist of accepted image MIME types mapped to a fixed, safe extension.
    // The extension used on disk is derived from this table, never from the
    // client-supplied filename, so a renamed .php/.phtml payload cannot land
    // with an executable extension.
    $allowedMimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];

    // Validate the upload is actually an image by inspecting its real content
    // (via the fileinfo extension), not the client-supplied name or the
    // client-supplied Content-Type header, both of which are attacker
    // controlled and easy to spoof.
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMime = $finfo !== false ? finfo_file($finfo, $tmpName) : false;
    if ($finfo !== false) {
        finfo_close($finfo);
    }

    if ($detectedMime === false || !isset($allowedMimeToExt[$detectedMime])) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    // getimagesize() additionally confirms the file decodes as a valid image
    // (catching polyglot files that pass the MIME sniff but aren't well-formed
    // images).
    if (@getimagesize($tmpName) === false) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    if (!is_dir($uploadDir) && !mkdir($uploadDir, 0755, true) && !is_dir($uploadDir)) {
        http_response_code(500);
        echo 'Upload failed.';
        return;
    }

    // The filename is generated server-side; the original client filename is
    // discarded entirely so it cannot influence the extension, path, or name
    // written to disk.
    $ext = $allowedMimeToExt[$detectedMime];
    $safeName = bin2hex(random_bytes(16)) . '.' . $ext;
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

The fix removes the client-supplied filename from the trust boundary entirely instead of trying to sanitize it. Two checks establish that the upload is genuinely an image: `finfo_file()` sniffs the real content-based MIME type of the uploaded bytes (not the spoofable `name`/`type` fields from `$_FILES`) against a small allowlist, and `getimagesize()` confirms the bytes decode as a valid image, which rejects polyglot files crafted to pass a MIME sniff while still carrying executable content. The on-disk extension is then taken only from the allowlist table keyed by the detected MIME type, so it can only ever be `jpg`, `png`, `gif`, or `webp` — never `.php` or any other server-executable extension, regardless of what the client's filename claimed. The filename itself is replaced with a random hex string, which also closes off path-traversal and overwrite concerns from `$originalName` (e.g. `../../` sequences) as a side effect, and `move_uploaded_file()`'s return value is now checked so a failed move is reported rather than silently claimed as success.
