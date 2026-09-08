## Verdict

Exploitable. `handleAvatarUpload()` writes the uploaded file to disk with `move_uploaded_file()` using a destination path built directly from the client-supplied `$_FILES['avatar']['name']`, with no check of the file's real content type and no allowlist of permitted extensions. An attacker can submit a file named e.g. `shell.php` (or a double extension such as `shell.php.jpg` depending on server configuration) and have it stored, byte-for-byte, under an attacker-chosen name and extension inside the upload directory.

## Source

`$_FILES['avatar']['name']` (client-supplied original filename) and `$_FILES['avatar']['tmp_name']` (the uploaded file's temporary path), both from the `$_FILES` superglobal populated by the multipart upload request in `handleAvatarUpload()`.

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

    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'Upload failed.';
        return;
    }

    $allowedMimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];

    $tmpName = $_FILES['avatar']['tmp_name'];

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedType = finfo_file($finfo, $tmpName);
    finfo_close($finfo);

    if ($detectedType === false || !isset($allowedMimeToExt[$detectedType])) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    $extension = $allowedMimeToExt[$detectedType];
    $uploadDir = __DIR__ . '/uploads/avatars/';
    $storedName = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . $storedName;

    move_uploaded_file($tmpName, $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The original code trusted the client-supplied filename as both the storage name and the storage extension, so `move_uploaded_file()` would write any content under any extension the attacker chose. The fix keeps the existing `UPLOAD_ERR_OK` check, then verifies the Fileinfo extension is loaded (calling `finfo_open`/`finfo_file` on a build without it is a fatal error, not a validation failure), detects the file's real MIME type from its content via `finfo_open(FILEINFO_MIME_TYPE)` + `finfo_file()`, and checks that type against a fixed allowlist of image types (`image/jpeg`, `image/png`, `image/gif`, `image/webp`). The extension used for storage is taken from the allowlist map entry that matched the detected type - never from the client-supplied name - which closes the double-extension bypass (e.g. `shell.php.jpg`) as well as the simple case. The stored filename itself is replaced with a random value (`bin2hex(random_bytes(16))`) so the original filename never reaches the filesystem at all, eliminating path-traversal and overwrite concerns tied to it in addition to the type confusion. Uploads whose real content does not match an allowed image type, or whose type cannot be detected, are now rejected with a 400 response instead of being stored.

## Behaviour changes

- Uploads whose real (content-detected) type is not one of `image/jpeg`, `image/png`, `image/gif`, `image/webp` are now rejected (HTTP 400, "Upload failed.") where they previously succeeded. This is the intended effect of the fix - closing the unrestricted-upload weakness necessarily changes what is accepted.
- If the `fileinfo` extension is not loaded, the request now fails with HTTP 500 instead of attempting the upload. This is a new failure mode required by the guidance (calling `finfo_open`/`finfo_file` without the extension loaded would otherwise be a fatal PHP `Error`, indistinguishable from a silently-skipped check).
- The stored filename and extension are now server-generated (`bin2hex(random_bytes(16)) . '.' . $extension`) rather than derived from `$_FILES['avatar']['name']`. Any accepted upload is now stored under a different filename than before; nothing in this file reads the filename back, so no downstream behaviour in the given code depends on it. If other code elsewhere in the application expects the avatar to be retrievable by its original client-supplied name, that code will need to be updated to use the generated name instead (e.g. by persisting it alongside the user's profile record).
- `move_uploaded_file()`'s return value is still ignored, unchanged from the original.
- The upload directory (`__DIR__ . '/uploads/avatars/'`) is unchanged. Per the loaded guidance, storing outside the document root and disabling script execution in the upload directory are recommended defence-in-depth measures, but they are server/deployment configuration rather than a code change in this file, so they are not applied here and are called out as a residual, out-of-scope hardening step.

## Verification

Ran `php -l` (PHP 8.5 CLI linter) against the fixed file in a scratch copy outside the case directory: "No syntax errors detected". All newly introduced names - `extension_loaded()`, `finfo_open()`, `finfo_file()`, `finfo_close()`, `FILEINFO_MIME_TYPE`, `bin2hex()`, `random_bytes()` - are PHP core/standard-library functions and constants (Fileinfo extension and core PHP, respectively), matching the calls the loaded `cwe/434/php/INDEX.md` guidance names explicitly (`finfo_open(FILEINFO_MIME_TYPE)` + `finfo_file()`, `extension_loaded('fileinfo')`, and `bin2hex(random_bytes(16))`), so none are unverified.
