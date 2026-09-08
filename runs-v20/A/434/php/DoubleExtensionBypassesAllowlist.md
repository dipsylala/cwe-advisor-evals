## Verdict

Confirmed. The extension check at line 21 uses `strpos()` to test whether an allowed extension appears *anywhere* in the filename, rather than checking the filename's actual (final) extension. A file named e.g. `avatar.jpg.php` contains the substring `.jpg`, so it passes the allowlist check, but it is saved under its original name — `.php` remains the file's true, last extension. If the destination directory is web-accessible and the server executes `.php` files (the common default), this uploads and makes reachable an executable script, i.e. arbitrary code execution via file upload.

## Source

`$_FILES['avatar']` (the multipart upload), specifically `$file['name']` (client-supplied, attacker-controlled filename) flowing unchanged into `$destination` and then into `move_uploaded_file()` at line 36.

## Fix

### File: DoubleExtensionBypassesAllowlist.php
```php
<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by checking the filename against
 * an allowlist of image extensions before storing the file.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    $originalName = $file['name'];

    // Determine the filename's actual (final) extension rather than
    // checking whether an allowed extension appears anywhere in the
    // name - a substring check lets "avatar.jpg.php" pass because it
    // contains ".jpg", even though its real extension is ".php".
    $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
    if (!in_array($extension, $allowedExtensions, true)) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Confirm the upload is genuine image data, not just a file whose
    // name happens to end in an image extension.
    $imageInfo = @getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Do not reuse the client-supplied filename for storage. Generate a
    // new random name with the verified extension so neither a double
    // extension, a path-traversal sequence, nor a null byte in the
    // original name can influence where or how the file is stored.
    $safeName = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . '/' . $safeName;

    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

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

The original check tokenized nothing: `strpos(strtolower($originalName), $ext) !== false` matches an allowed extension string appearing anywhere in the filename, including in the middle. Combined with keeping the attacker's original filename verbatim (`$destination = $uploadDir . '/' . $originalName`), a name like `shell.jpg.php` (or `shell.png%00.php` on older PHP, or a name with `../` in it) sails through the allowlist while still carrying its real, executable extension on disk.

The fix makes three independent changes, each closing a distinct part of the gap:

1. **Extension check now targets the real extension.** `pathinfo($originalName, PATHINFO_EXTENSION)` returns only the substring after the last dot, so `shell.jpg.php` yields `php`, which the allowlist correctly rejects. This alone defeats the double-extension bypass described in the finding.
2. **Content verification.** `getimagesize()` parses the file's actual header/structure; a file that is not valid image data fails even if it somehow carried an allowed extension, guarding against extension spoofing more generally.
3. **Filename is no longer attacker-controlled.** Storage uses a freshly generated random name plus the verified extension instead of `$originalName`. This removes path traversal, null-byte truncation, and any other filename-based trick as an avenue, independent of the extension logic - the stored file's name and extension are now fully determined by server-side logic, not client input.

Together these mean the destination path and its extension are never derived from attacker-supplied data, so no filename crafted by the client - double extension or otherwise - can cause a non-image, executable file to be written into the upload directory.
